
use hyper::server::conn::http1;
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use hyper::service::Service;
use std::pin::Pin;
use std::future::Future;
use hyper_util::rt::tokio::{TokioIo, TokioTimer};
use tokio::signal::unix::{signal, SignalKind};
use log::{info,warn,error};
use tokio::net::TcpStream;

mod config;
mod ssl;

#[derive(Clone)]
struct Svc {
	cfg: config::Config,
}

impl Svc {
	fn new(cfg: config::Config) -> Self {
		Self { cfg }
	}
}

impl Service<Request<Incoming>> for Svc {
	type Response = Response<Incoming>;
	type Error = hyper::Error;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn call(&self, req: Request<Incoming>) -> Self::Future {
		/*fn mk_response(s: String) -> Result<Response<Full<Bytes>>, hyper::Error> {
			Ok(Response::builder().body(Full::new(Bytes::from(s))).unwrap())
		}*/

		let uri = req.uri();

		info!("REQUEST {} {} {}", req.method(), uri.path(), uri.query().unwrap_or("-"));
		let hdrs = req.headers();

		let mut remote_request = Request::builder()
			.method(req.method())
			.uri(req.uri());

		let mut host_done = false;
		for (key, value) in hdrs.iter() {
			// info!(" -> {:?}: {:?}", key, value);
			if key == "host" {
				if let Some(repl) = self.cfg.get_rewrite_host() {
					remote_request = remote_request.header(key, repl);
					host_done = true;
					continue;
				}
			}
			remote_request = remote_request.header(key, value);
		}
		if !host_done {
			if let Some(repl) = self.cfg.get_rewrite_host() {
				remote_request = remote_request.header("host", repl);
			}
		}

		let cfg = self.cfg.clone();

		Box::pin(async move {
			let address = cfg.get_remote();

			let remote_request = remote_request.body(req.into_body()).unwrap();

			if cfg.use_ssl() {
				let stream = TcpStream::connect(address).await.unwrap();
				let stream = ssl::wrap( stream, cfg ).await.unwrap();

				let io = TokioIo::new( stream );
				let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
				tokio::task::spawn(async move {
					if let Err(err) = conn.await {
						info!("Connection failed: {:?}", err);
					}
				});
				Ok(sender.send_request(remote_request).await.unwrap())
			} else {
				let stream = TcpStream::connect(address).await.unwrap();
				let io = TokioIo::new(stream);
				let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
				tokio::task::spawn(async move {
					if let Err(err) = conn.await {
						info!("Connection failed: {:?}", err);
					}
				});
				Ok(sender.send_request(remote_request).await.unwrap())
			}






/*
			let mut fs = req.into_body();
			loop {
				let item = fs.frame().await;
				if item.is_none() {
					info!("None");
					break;
				}
				match item.unwrap() {
					Ok(frm) => {
						if let Ok(data) = frm.into_data() {
							for ch in data.into_iter() {
								info!("RU: {}", ch);
							}
						}
					},
					Err(e) => {
						error!("Data read failed {}", e);
						break;
					}
				}
			}
*/

/*
			let frame_stream = req.into_body().map_frame(|frame| {
				let frame = if let Ok(data) = frame.into_data() {
					data.iter()
						.map(|byte| {
							byte.to_ascii_uppercase()
						})
						.collect::<Bytes>()
				} else {
					Bytes::new()
				};

				Frame::data(frame)
			});
*/
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
	simple_logger::SimpleLogger::new().init().unwrap();

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

