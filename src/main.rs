
use hyper::server::conn::http1;
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::net::{TcpStream,TcpListener};
use hyper::service::Service;
use std::pin::Pin;
use std::future::Future;
use hyper_util::rt::tokio::{TokioIo, TokioTimer};
use tokio::signal::unix::{signal, SignalKind};
use log::{info,warn,error};
use core::task::{Context,Poll};
use hyper::body::Frame;
use tokio::io::{AsyncRead,AsyncWrite};
use hyper::rt::{Read,Write};
use core::marker::Unpin;
use async_trait::async_trait;

mod config;
mod ssl;
mod logcfg;

macro_rules! errmg {
	($arg: expr) => {
		($arg).map_err(|e| format!("{:?} at {}:{}", e, file!(), line!()))
	}
}

enum GatewayBody {
	Incoming(hyper::body::Incoming),
	Empty,
}
impl hyper::body::Body for GatewayBody where {
	type Data = hyper::body::Bytes;
	type Error = hyper::Error;

	fn poll_frame( self: Pin<&mut Self>, cx: &mut Context<'_>,) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		match &mut *self.get_mut(){
			Self::Incoming(incoming) => Pin::new(incoming).poll_frame(cx),
			Self::Empty => Poll::Ready(None)
		}
	}
}

trait Stream : AsyncRead + AsyncWrite + Unpin + Send { }
impl<T> Stream for T where T : AsyncRead + AsyncWrite + Unpin + Send { }

#[async_trait]
trait Sender : Send {
	async fn send(&mut self, req: Request<GatewayBody>) -> hyper::Result<Response<Incoming>>;
}

#[async_trait]
impl Sender for hyper::client::conn::http1::SendRequest<GatewayBody> {
	async fn send(&mut self, req: Request<GatewayBody>) -> hyper::Result<Response<Incoming>> {
		self.send_request(req).await
	}
}
#[async_trait]
impl Sender for hyper::client::conn::http2::SendRequest<GatewayBody> {
	async fn send(&mut self, req: Request<GatewayBody>) -> hyper::Result<Response<Incoming>> {
		self.send_request(req).await
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

	async fn connect(address: (String,u16), cfg: config::Config) -> Result<Box<dyn Stream>,String> {
		if cfg.client_use_ssl() {
			let stream = errmg!(TcpStream::connect(address).await)?;
			let stream = ssl::wrap( stream, cfg ).await?;
			Ok(Box::new(stream))
		} else {
			let stream = errmg!(TcpStream::connect(address).await)?;
			Ok(Box::new(stream))
		}
	}

	async fn handshake(io: TokioIo<Box<dyn Stream>>, cfg: config::Config) -> Result<Box<dyn Sender>, String> {

/*
		let (mut sender, conn) = match remote_proto {
			HttpVersionMode::V1 => errmg!(hyper::client::conn::http1::handshake(io).await)?,
			HttpVersionMode::V2Direct => {
				let executor = hyper_util::rt::tokio::TokioExecutor::new();
				errmg!(hyper::client::conn::http2::handshake(executor, io).await)?
			},
			HttpVersionMode::V2Handshake => {
				let executor = hyper_util::rt::tokio::TokioExecutor::new();
				errmg!(hyper::client::conn::http2::handshake(executor, io).await)?
			},
		};
*/

		let (mut sender, conn) = errmg!(hyper::client::conn::http1::handshake(io).await)?;
		tokio::task::spawn(async move {
			if let Err(err) = conn.await {
				warn!("Connection failed: {:?}", err);
			}
		});
		Ok(Box::new(sender))
	}


	async fn forward(cfg: config::Config, req: Request<Incoming>) -> Result<Response<Incoming>,String> {
		let hdrs = req.headers();

		let mut remote_request = Request::builder()
			.method(req.method())
			.uri(req.uri());

		let mut host_done = false;
		for (key, value) in hdrs.iter() {
			if cfg.log_headers() {
				info!(" -> {:?}: {:?}", key, value);
			}
			if key == "host" {
				if let Some(repl) = cfg.get_rewrite_host() {
					remote_request = remote_request.header(key, repl);
					host_done = true;
					continue;
				}
			}
			remote_request = remote_request.header(key, value);
		}
		if !host_done {
			if let Some(repl) = cfg.get_rewrite_host() {
				remote_request = remote_request.header("host", repl);
			}
		}

		let address = cfg.get_remote();

		let remote_request = errmg!(remote_request.body(req.into_body()))?;
		let remote_proto = cfg.client_version();

		let stream = errmg!(Self::connect(address, cfg.clone()).await)?;
		let io = TokioIo::new( stream );
		let mut sender = errmg!(Self::handshake(io, cfg.clone()).await)?;
		errmg!(sender.send(remote_request.map(|v| GatewayBody::Incoming(v))).await)
	}
}

impl Service<Request<Incoming>> for Svc {
	type Response = Response<GatewayBody>;
	type Error = String;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn call(&self, req: Request<Incoming>) -> Self::Future {
		let uri = req.uri();

		info!("REQUEST {} {} {}", req.method(), uri.path(), uri.query().unwrap_or("-"));

		let loghdr = self.cfg.log_headers();
		let cfg = self.cfg.clone();
		Box::pin(async move {
			match Self::forward(cfg, req).await {
				Ok(remote_resp) => {
					if loghdr {
						remote_resp.headers().iter().for_each(|(k,v)| info!(" <- {:?}: {:?}", k, v));
					}

					Ok(remote_resp.map(|v| GatewayBody::Incoming(v)))
				},
				Err(e) => {
					error!("Call forward failed: {:?}", e);
					errmg!(Response::builder()
						.status(502)
						.body(GatewayBody::Empty))
				}
			}
		})
	}
}

async fn shutdown_signal() {
	signal(SignalKind::interrupt())
		.expect("failed to install SIGINT signal handler")
		.recv()
		.await;
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	logcfg::init_logging();

	let cfg = match config::Config::load("config.toml") {
		Ok(v) => v,
		Err(e) => panic!("{}", e)
	};

	let addr = cfg.get_bind();

	let svc = Svc::new(cfg.clone());

	let graceful = hyper_util::server::graceful::GracefulShutdown::new();
	let mut signal = std::pin::pin!(shutdown_signal());

	let listener = TcpListener::bind(addr).await?;
	info!("Listening on http://{}", addr);
	loop {
		tokio::select! {
			Ok((tcp, _addr)) = listener.accept() => {
				let io = TokioIo::new(tcp);
				let svc_clone = svc.clone();
				let conn = http1::Builder::new()
						.timer(TokioTimer::new())
						.serve_connection(io, svc_clone);
				let fut = graceful.watch(conn);
				tokio::task::spawn(async move {
					if let Err(err) = fut.await {
						error!("Error serving connection: {:?}", err);
					}
				});
			},
			_ = &mut signal => {
				info!("graceful shutdown signal received");
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

