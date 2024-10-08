
use hyper::body::Incoming;
use hyper::{Request,Response,StatusCode,HeaderMap};
use tokio::net::TcpStream;
use hyper::service::Service;
use std::pin::Pin;
use std::future::Future;
use std::sync::{Arc,Mutex};
use std::error::Error;
use std::fmt;
use std::fmt::Debug;
use hyper_util::rt::tokio::TokioIo;
use log::{debug,info,warn,error};
use std::time::Duration;
use std::net::SocketAddr;

use crate::pool::{remote_pool_key,remote_pool_get,remote_pool_release};
use crate::net::{Stream,Sender,GatewayBody,config_socket};
use crate::config::{Config,RemoteConfig,ConfigAction,SslData};
use crate::lua;

pub struct ServiceError {
	message: String,
	status: StatusCode,
	body: GatewayBody,
	source: Option<Box<dyn Error + Send>>,
}

impl ServiceError {
	pub fn remap<T>(message: String, status: StatusCode, e: T) -> Self where T: Error + Send + 'static {
		Self {
			message: message,
			status: status,
			body: GatewayBody::empty(),
			source: Some(Box::new(e)),
		}
	}
}

impl fmt::Display for ServiceError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.message)
	}
}

impl Debug for ServiceError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.message)
	}
}

impl Error for ServiceError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match &self.source {
			None => None,
			Some(bxe) => Some(bxe.as_ref()),
		}
	}
}

impl From<String> for ServiceError {
	fn from(message: String) -> Self {
		Self {
			message: message,
			status: StatusCode::BAD_GATEWAY,
			body: GatewayBody::empty(),
			source: None,
		}
	}
}

macro_rules! errmg {
	($arg: expr) => {
		($arg).map_err(|e| ServiceError::remap(
			format!("{:?} at {}:{}", e, file!(), line!()),
			StatusCode::BAD_GATEWAY, e
		))
	}
}
pub(crate) use errmg;

struct CachedSender {
	key: String,
	value: Box<dyn Sender>,
}

#[derive(Clone)]
pub struct GatewayService {
	cfg: Arc<Mutex<Config>>,
	original_cfg: Config,
	client: Option<SocketAddr>,
}

impl GatewayService {
	pub fn new(cfg: Config) -> Self {
		Self {
			cfg: Arc::new(Mutex::new(cfg.clone())),
			original_cfg: cfg,
			client: None,
		}
	}

	pub fn set_client(&mut self, value: SocketAddr) {
		self.client = Some(value);
	}
	fn get_client(&self) -> String {
		match self.client {
			Some(v) => v.to_string(),
			None => "N/A".to_string(),
		}
	}

	async fn connect(address: (String,u16), ssldata: SslData, remote: &RemoteConfig, log_stream: bool) -> Result<Box<dyn Stream>, ServiceError> {
		let stream = errmg!(TcpStream::connect(address).await)?;
		config_socket!(stream);

		if remote.ssl() {
			let stream = crate::ssl::wrap_client( stream, ssldata, remote ).await?;
			if log_stream {
				let stream = crate::net::LoggingStream::wrap(stream);
				Ok(Box::new(stream))
			} else {
				Ok(Box::new(stream))
			}
		} else {
			if log_stream {
				let stream = crate::net::LoggingStream::wrap(stream);
				Ok(Box::new(stream))
			} else {
				Ok(Box::new(stream))
			}
		}
	}

	fn log_headers(hdrs: &HeaderMap, client_addr: &str, corr_id: &str, step: &str) {
		for (key, value) in hdrs.iter() {
			info!("{}{} {} {:?}: {:?}", corr_id, client_addr, step, key, value);
		}
	}

	fn log_request(action: &ConfigAction, req: &Request<GatewayBody>, client_addr: &str, corr_id: &str, step: &str) {
		if action.log() {
			let uri = req.uri().clone();
			info!("{}{} {} {:?} {} {} {} {} {}",
				corr_id, client_addr, step,
				req.version(),
				req.method(),
				uri.scheme().map(|v| v.as_str()).unwrap_or("-"),
				uri.authority().map(|v| v.as_str()).unwrap_or("-"),
				uri.path(),
				uri.query().unwrap_or("-"));
		}

		if action.log_headers() {
			Self::log_headers(req.headers(), client_addr, corr_id, step);
		}

	}

	fn log_reply(action: &ConfigAction, rep: &Response<GatewayBody>, client_addr: &str, corr_id: &str, step: &str) {
		if action.log() {
			info!("{}{} {} {:?} {:?}", corr_id, client_addr, step, rep.version(), rep.status());
		}

		if action.log_headers() {
			Self::log_headers(rep.headers(), client_addr, corr_id, step);
		}
	}

	async fn mangle_request(cfg: &Config, action: &ConfigAction, req: Request<Incoming>, client_addr: &str, corr_id: &str) -> Result<Request<GatewayBody>, ServiceError> {
		let req = req.map(|v| {
			let mut body = GatewayBody::wrap(v);
			if action.log_request_body() {
				body.log_payload(true, action.max_request_log_size(), format!("{}->PAYLOAD ", corr_id));
			}
			body
		});
		Self::log_request(action, &req, client_addr, corr_id, "->R");
		let modified_request = action.client_version().adapt_request(cfg, action, req, corr_id)?;
		let modified_request = action.adapt_request(modified_request, corr_id)?;
		let modified_request = lua::apply_request_script(&action, modified_request, client_addr, corr_id).await?;
		Self::log_request(action, &modified_request, client_addr, corr_id, "R->");
		Ok(modified_request)
	}

	async fn mangle_reply(action: &ConfigAction, remote_resp: Response<Incoming>, client_addr: &str, corr_id: &str) -> Result<Response<GatewayBody>, ServiceError> {
		let response = remote_resp.map(|v| {
			let mut body = GatewayBody::wrap(v);
			if action.log_reply_body() {
				body.log_payload(true, action.max_reply_log_size(), format!("{}<-PAYLOAD ", corr_id));
			}
			body
		});
		Self::log_reply(action, &response, client_addr, corr_id, "R<-");
		let modified_response = action.client_version().adapt_response(action, response)?;
		let modified_response = action.adapt_response(modified_response, corr_id)?;
		let modified_response = lua::apply_response_script(&action, modified_response, client_addr, corr_id).await?;
		Self::log_reply(action, &modified_response, client_addr, corr_id, "<-R");
		Ok(modified_response)
	}

	async fn get_sender(cfg: &Config, action: &ConfigAction) -> Result<CachedSender, ServiceError> {
		let remote = action.get_remote();
		let address = remote.address();
		let httpver = action.client_version();
		let conn_pool_key = remote_pool_key!(address,httpver);
		let ssldata: SslData = (action.get_ssl_mode(), httpver, action.get_ca_file());

		let sender = if let Some(mut pool) = remote_pool_get!(&conn_pool_key) {
			if pool.check().await {
				Some(pool)
			} else {
				None
			}
		} else {
			None
		};

		let sender = if let Some(v) = sender {
			v
		} else {
			let stream = Self::connect(address, ssldata, &remote, cfg.log_stream()).await?;
			let io = TokioIo::new( stream );
			httpver.handshake(remote.raw(), io).await?
		};

		Ok(CachedSender {
			key: conn_pool_key,
			value: sender,
		})
	}

	async fn forward(cfg: &Config, action: &ConfigAction, req: Request<Incoming>, client_addr: &str, corr_id: &str) -> Result<Response<Incoming>, ServiceError> {
		let remote_request = Self::mangle_request(cfg, action, req, client_addr, corr_id).await?;
		let mut sender = Self::get_sender(cfg, action).await?;
		let rv = errmg!(sender.value.send(remote_request).await);

		remote_pool_release!(&sender.key, sender.value);
		rv
	}
}

impl Service<Request<Incoming>> for GatewayService {
	type Response = Response<GatewayBody>;
	type Error = hyper::http::Error;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn call(&self, req: Request<Incoming>) -> Self::Future {
		let uri = req.uri().clone();
		let method = req.method().clone();
		let headers = req.headers().clone();
		let cfg_local = self.cfg.clone();
		let client_addr = self.get_client();

		let mut cfg = (*cfg_local.lock().unwrap_or_else(|mut e| {
			**e.get_mut() = self.original_cfg.clone();
			cfg_local.clear_poison();
			e.into_inner()
		})).clone();

		let (action, rules) = cfg.get_request_config(&method, &uri, &headers);

		Box::pin(async move {
			let corr_id = format!("{:?} ", uuid::Uuid::new_v4());
			if action.log() {
				if rules.is_empty() {
					debug!("{}No rules found", corr_id);
				} else {
					debug!("{}Using rules: {}", corr_id, rules.join(","));
				}
			}

			let remote_resp = match Self::forward(&cfg, &action, req, &client_addr, &corr_id).await {
				Err(e) => {
					error!("Call forward failed: {:?}", e.message);
					return Response::builder()
						.status(e.status)
						.body(e.body);
				},
				Ok(remote_resp) => remote_resp,
			};

			if let Ok(mut locked) = cfg_local.lock() {
				let status = remote_resp.status();
				locked.notify_reply(rules, &status);
			}

			match Self::mangle_reply(&action, remote_resp, &client_addr, &corr_id).await {
				Ok(v) => Ok(v),
				Err(e) => {
					error!("Call forward failed: {:?}", e.message);
					Response::builder()
						.status(e.status)
						.body(e.body)
				}
			}
		})
	}
}

