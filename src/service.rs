
use hyper::body::Incoming;
use hyper::{Request,Response,StatusCode};
use tokio::net::TcpStream;
use hyper::service::Service;
use std::pin::Pin;
use std::future::Future;
use std::sync::{Arc,Mutex};
use std::error::Error;
use std::fmt;
use std::fmt::Debug;
use hyper_util::rt::tokio::TokioIo;
use log::{debug,info,warn,error,log_enabled,Level};
use std::time::Duration;

use crate::pool::{remote_pool_key,remote_pool_get,remote_pool_release};
use crate::net::{Stream,Sender,GatewayBody,keepalive,config_socket};
use crate::config::{Config,RemoteConfig,ConfigAction,HttpVersionMode,SslData};

pub struct ServiceError {
	message: String,
	status: StatusCode,
	body: GatewayBody,
	source: Option<Box<dyn Error>>,
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
		($arg).map_err(|e| ServiceError {
			message: format!("{:?} at {}:{}", e, file!(), line!()),
			status: StatusCode::BAD_GATEWAY,
			body: GatewayBody::empty(),
			source: Some(Box::new(e)),
		})
	}
}

struct CachedSender {
	key: String,
	value: Box<dyn Sender>,
}

#[derive(Clone)]
pub struct GatewayService {
	cfg: Arc<Mutex<Config>>,
	original_cfg: Config,
}

impl GatewayService {
	pub fn new(cfg: Config) -> Self {
		Self {
			cfg: Arc::new(Mutex::new(cfg.clone())),
			original_cfg: cfg,
		}
	}

	async fn connect(address: (String,u16), ssldata: SslData, remote: &RemoteConfig) -> Result<Box<dyn Stream>, ServiceError> {
		let stream = errmg!(TcpStream::connect(address).await)?;
		config_socket!(stream);

		if remote.ssl() {
			let stream = crate::ssl::wrap_client( stream, ssldata, remote ).await?;
			if log_enabled!(Level::Trace) {
				let stream = crate::net::LoggingStream::wrap(stream);
				Ok(Box::new(stream))
			} else {
				Ok(Box::new(stream))
			}
		} else {
			if log_enabled!(Level::Trace) {
				let stream = crate::net::LoggingStream::wrap(stream);
				Ok(Box::new(stream))
			} else {
				Ok(Box::new(stream))
			}
		}
	}

	async fn handshake(io: TokioIo<Box<dyn Stream>>, httpver: HttpVersionMode) -> Result<Box<dyn Sender>, ServiceError> {
		match httpver {
			HttpVersionMode::V1 => {
				let (sender, conn) = errmg!(hyper::client::conn::http1::handshake(io).await)?;
				keepalive!(conn);
				Ok(Box::new(sender))
			},
			HttpVersionMode::V2Direct => {
				let executor = hyper_util::rt::tokio::TokioExecutor::new();
				let (sender, conn) = errmg!(hyper::client::conn::http2::handshake(executor, io).await)?;
				keepalive!(conn);
				Ok(Box::new(sender))
			},
			HttpVersionMode::V2Handshake => {
				let executor = hyper_util::rt::tokio::TokioExecutor::new();
				let (sender, conn) = errmg!(hyper::client::conn::http2::handshake(executor, io).await)?;
				// TODO: h2 handshake

				keepalive!(conn);
				Ok(Box::new(sender))
			},
		}
	}

	fn mangle_request(cfg: &ConfigAction, req: Request<Incoming>, corr_id: &str) -> Result<Request<GatewayBody>, ServiceError> {
		let req = req.map(|v| {
			let mut body = GatewayBody::wrap(v);
			if cfg.log_request_body() {
				body.log_payload(true, cfg.max_request_log_size(), format!("{}REQUEST ", corr_id));
			}
			body
		});

		if cfg.log() {
			let uri = req.uri().clone();
			info!("{}REQUEST {:?} {} {} {}", corr_id, req.version(), req.method(), uri.path(), uri.query().unwrap_or("-"));
		}

		let hdrs = req.headers();

		let mut modified_request = Request::builder()
			.method(req.method())
			.uri(req.uri());

		let mut host_done = false;
		let loghdr = cfg.log_headers();
		for (key, value) in hdrs.iter() {
			if loghdr {
				info!("{} -> {:?}: {:?}", corr_id, key, value);
			}
			if key == "host" {
				if let Some(repl) = cfg.get_rewrite_host() {
					modified_request = modified_request.header(key, repl);
					host_done = true;
					continue;
				}
			}
			modified_request = modified_request.header(key, value);
		}
		if !host_done {
			if let Some(repl) = cfg.get_rewrite_host() {
				modified_request = modified_request.header("host", repl);
			}
		}

		errmg!(modified_request.body(req.into_body()))
	}

	fn mangle_reply(cfg: &ConfigAction, remote_resp: Response<Incoming>, corr_id: &str) -> Result<Response<GatewayBody>, ServiceError> {
		if cfg.log() {
			let status = remote_resp.status();
			info!("{}REPLY {:?} {:?}", corr_id, remote_resp.version(), status);
		}
		if cfg.log_headers() {
			remote_resp.headers().iter().for_each(|(k,v)| info!("{} <- {:?}: {:?}", corr_id, k, v));
		}

		Ok(remote_resp.map(|v| {
			let mut body = GatewayBody::wrap(v);
			if cfg.log_reply_body() {
				body.log_payload(true, cfg.max_reply_log_size(), format!("{}REPLY ", corr_id));
			}
			body
		}))
	}

	async fn get_sender(cfg: &ConfigAction) -> Result<CachedSender, ServiceError> {
		let remote = cfg.get_remote();
		let address = remote.address();
		let conn_pool_key = remote_pool_key!(address);
		let httpver = cfg.client_version();
		let ssldata: SslData = (cfg.get_ssl_mode(), httpver, cfg.get_ca_file());

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
			let stream = Self::connect(address, ssldata, &remote).await?;
			let io = TokioIo::new( stream );
			Self::handshake(io, httpver).await?
		};

		Ok(CachedSender {
			key: conn_pool_key,
			value: sender,
		})
	}

	async fn forward(cfg: &ConfigAction, req: Request<Incoming>, corr_id: &str) -> Result<Response<Incoming>, ServiceError> {
		let remote_request = Self::mangle_request(cfg, req, corr_id)?;
		let mut sender = Self::get_sender(cfg).await?;
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

		let (cfg,rules) = (*cfg_local.lock().unwrap_or_else(|mut e| {
			**e.get_mut() = self.original_cfg.clone();
			cfg_local.clear_poison();
			e.into_inner()
		})).get_request_config(&method, &uri, &headers);

		Box::pin(async move {
			let corr_id = format!("{:?} ", uuid::Uuid::new_v4());
			if cfg.log() {
				if rules.is_empty() {
					debug!("{}No rules found", corr_id);
				} else {
					debug!("{}Using rules: {}", corr_id, rules.join(","));
				}
			}

			Self::forward(&cfg, req, &corr_id)
				.await
				.and_then(|remote_resp| {
					if let Ok(mut locked) = cfg_local.lock() {
						let status = remote_resp.status();
						locked.notify_reply(rules, &status);
					}
					Self::mangle_reply(&cfg, remote_resp, &corr_id)
				}).or_else(|e| {
					error!("Call forward failed: {:?}", e.message);
					Response::builder()
						.status(e.status)
						.body(e.body)
				})
		})
	}
}

