
use hyper::server::conn::http1;
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::net::{TcpStream,TcpListener};
use hyper::service::Service;
use std::pin::Pin;
use std::future::Future;
use hyper_util::rt::tokio::{TokioIo, TokioTimer};
use tokio::signal::unix::{signal, SignalKind};
use log::{debug,info,warn,error};
use std::time::Duration;

use pool::{remote_pool_key,remote_pool_get,remote_pool_release};
use net::{Stream,Sender,GatewayBody};
use config::SslData;

mod pool;
mod config;
mod ssl;
mod logcfg;
mod net;

macro_rules! errmg {
	($arg: expr) => {
		($arg).map_err(|e| format!("{:?} at {}:{}", e, file!(), line!()))
	}
}

macro_rules! keepalive {
	($arg: expr) => {
		tokio::task::spawn(async move {
			if let Err(err) = $arg.await {
				warn!("Connection failed: {:?}", err);
			}
		});
	}
}

macro_rules! config_socket {
	($sock: expr) => {
		$sock.set_linger(Some(Duration::from_secs(0))).unwrap_or_else(|err| { warn!("{}:{} Failed to set SO_LINGER on socket: {:?}", file!(), line!(), err); () });
	}
}

#[derive(Clone)]
struct Svc {
	cfg: config::Config,
}

impl Svc {
	fn new(cfg: config::Config) -> Self {
		Self { cfg }
	}

	async fn connect(address: (String,u16), ssldata: SslData, remote: &config::RemoteConfig) -> Result<Box<dyn Stream>,String> {
		if remote.ssl() {
			let stream = errmg!(TcpStream::connect(address).await)?;
			config_socket!(stream);
			let stream = ssl::wrap_client( stream, ssldata, remote ).await?;
			Ok(Box::new(stream))
		} else {
			let stream = errmg!(TcpStream::connect(address).await)?;
			config_socket!(stream);
			Ok(Box::new(stream))
		}
	}

	async fn handshake(io: TokioIo<Box<dyn Stream>>, httpver: config::HttpVersionMode) -> Result<Box<dyn Sender>, String> {
		match httpver {
			config::HttpVersionMode::V1 => {
				let (sender, conn) = errmg!(hyper::client::conn::http1::handshake(io).await)?;
				keepalive!(conn);
				Ok(Box::new(sender))
			},
			config::HttpVersionMode::V2Direct => {
				let executor = hyper_util::rt::tokio::TokioExecutor::new();
				let (sender, conn) = errmg!(hyper::client::conn::http2::handshake(executor, io).await)?;
				keepalive!(conn);
				Ok(Box::new(sender))
			},
			config::HttpVersionMode::V2Handshake => {
				let executor = hyper_util::rt::tokio::TokioExecutor::new();
				let (sender, conn) = errmg!(hyper::client::conn::http2::handshake(executor, io).await)?;
				// TODO: h2 handshake

				keepalive!(conn);
				Ok(Box::new(sender))
			},
		}
	}


	async fn forward(cfg: config::Config, req: Request<GatewayBody>) -> Result<Response<Incoming>,String> {
		let hdrs = req.headers();

		let mut remote_request = Request::builder()
			.method(req.method())
			.uri(req.uri());

		let mut host_done = false;
		for (key, value) in hdrs.iter() {
			if cfg.log_headers(req.method(), req.uri(), req.headers()) {
				info!(" -> {:?}: {:?}", key, value);
			}
			if key == "host" {
				if let Some(repl) = cfg.get_rewrite_host(req.method(), req.uri(), req.headers()) {
					remote_request = remote_request.header(key, repl);
					host_done = true;
					continue;
				}
			}
			remote_request = remote_request.header(key, value);
		}
		if !host_done {
			if let Some(repl) = cfg.get_rewrite_host(req.method(), req.uri(), req.headers()) {
				remote_request = remote_request.header("host", repl);
			}
		}

		let remote = cfg.get_remote(req.method(), req.uri(), req.headers());
		let address = remote.address();
		let conn_pool_key = remote_pool_key!(address);
		let httpver = cfg.client_version(req.method(), req.uri(), req.headers());
		let ssldata: SslData = (
			cfg.get_ssl_mode(req.method(), req.uri(), req.headers()),
			httpver,
			cfg.get_ca_file(req.method(), req.uri(), req.headers())
		);

		let remote_request = errmg!(remote_request.body(req.into_body()))?;

		let sender = if let Some(mut pool) = remote_pool_get!(&conn_pool_key) {
			if pool.check().await {
				Some(pool)
			} else {
				None
			}
		} else {
			None
		};

		let mut sender = if let Some(v) = sender {
			v
		} else {
			let stream = errmg!(Self::connect(address, ssldata, &remote).await)?;
			let io = TokioIo::new( stream );
			errmg!(Self::handshake(io, httpver).await)?
		};

		let rv = errmg!(sender.send(remote_request).await);
		remote_pool_release!(&conn_pool_key, sender);
		rv
	}
}

impl Service<Request<Incoming>> for Svc {
	type Response = Response<GatewayBody>;
	type Error = String;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn call(&self, req: Request<Incoming>) -> Self::Future {
		let cfg = self.cfg.clone();
		Box::pin(async move {
			let uri = req.uri().clone();
			let method = req.method().clone();
			let headers = req.headers().clone();

			let simple_log = cfg.log(&method, &uri, &headers);
			let log_headers = cfg.log_headers(&method, &uri, &headers);

			let corr_id = if simple_log {
				format!("{:?} ", uuid::Uuid::new_v4())
			} else {
				"".to_string()
			};

			if simple_log {
				info!("{}REQUEST {} {} {}", corr_id, method, uri.path(), uri.query().unwrap_or("-"));
			}

			let req = req.map(|v| {
				let mut body = GatewayBody::wrap(v);
				body.log_payload(cfg.log_request_body(&method, &uri, &headers), corr_id.clone());
				body
			});

			match Self::forward(cfg, req).await {
				Ok(remote_resp) => {
					if simple_log {
						info!("{}REPLY {:?} {:?}", corr_id, remote_resp.version(), remote_resp.status());
					}
					if log_headers {
						remote_resp.headers().iter().for_each(|(k,v)| info!(" <- {:?}: {:?}", k, v));
					}

					Ok(remote_resp.map(|v| GatewayBody::wrap(v)))
				},
				Err(e) => {
					error!("Call forward failed: {:?}", e);
					errmg!(Response::builder()
						.status(502)
						.body(GatewayBody::empty()))
				}
			}
		})
	}
}

async fn shutdown_signal_int() {
	signal(SignalKind::interrupt())
		.expect("failed to install SIGINT signal handler")
		.recv()
		.await;
}

async fn shutdown_signal_term() {
	signal(SignalKind::terminate())
		.expect("failed to install SIGTERM signal handler")
		.recv()
		.await;
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	logcfg::init_logging();
	let args: Vec<String> = std::env::args().collect();

	let mut cfile = "config.toml";
	if args.len() > 2 {
		if args[1].eq("-f") {
			cfile = &args[2];
		}
	}

	info!("Looking for configuration file {}", cfile);
	let cfg = match config::Config::load(cfile) {
		Ok(v) => v,
		Err(e) => panic!("{}", e)
	};

	let addr = cfg.get_bind();

	let svc = Svc::new(cfg.clone());

	let graceful = hyper_util::server::graceful::GracefulShutdown::new();
	let mut signal_int = std::pin::pin!(shutdown_signal_int());
	let mut signal_term = std::pin::pin!(shutdown_signal_term());

	let ssl = cfg.server_ssl();
	let acceptor = if ssl {
		match ssl::get_ssl_acceptor(cfg.clone()) {
			Ok(v) => Some(v),
			Err(e) => {
				error!("{:?} at {} {}", e, file!(), line!());
				None
			}
		}
	} else { None };

	let listener = TcpListener::bind(addr).await?;
	info!("Listening on http{}://{}", if ssl { "s" } else { "" }, addr);
	loop {
		tokio::select! {
			Ok((tcp, _addr)) = listener.accept() => {
				config_socket!(tcp);
				let tcp: Option<Box<dyn Stream>> = if let Some(acc) = acceptor.clone() {
					match ssl::wrap_server(tcp, acc.clone()).await {
						Ok(v) => Some(Box::new(v)),
						Err(e) => {
							error!("{:?} at {} {}", e, file!(), line!());
							None
						}
					}
				} else {
					Some(Box::new(tcp))
				};
				if let Some(tcp) = tcp {
					let io = TokioIo::new(tcp);
					let svc_clone = svc.clone();
					let conn = http1::Builder::new()
							.timer(TokioTimer::new())
							.serve_connection(io, svc_clone);
					let fut = graceful.watch(conn);
					tokio::task::spawn(async move {
						if let Err(err) = fut.await {
							debug!("Client connection terminated {:?}", err);
						}
					});
				}
			},
			_ = &mut signal_int => {
				info!("shutdown signal SIGINT received");
				break;
			},
			_ = &mut signal_term => {
				info!("shutdown signal SIGTERM received");
				break;
			},
		}
	}

	tokio::select! {
		_ = graceful.shutdown() => {
			info!("all connections gracefully closed");
		},
		_ = tokio::time::sleep(cfg.get_graceful_shutdown_timeout()) => {
			warn!("timed out wait for all connections to close");
		}
	}

	Ok(())
}

