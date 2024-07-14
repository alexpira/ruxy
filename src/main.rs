
use bytes::Bytes;
use http_body_util::Full;
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
use hyper::body::Frame;
use http_body_util::BodyExt;

mod config;

#[derive(Clone)]
struct Svc {
}

impl Service<Request<Incoming>> for Svc {
	type Response = Response<Full<Bytes>>;
	type Error = hyper::Error;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn call(&self, req: Request<Incoming>) -> Self::Future {
		fn mk_response(s: String) -> Result<Response<Full<Bytes>>, hyper::Error> {
			Ok(Response::builder().body(Full::new(Bytes::from(s))).unwrap())
		}

		let uri = req.uri();

		info!("REQ {} {} {}", req.method(), uri.path(), uri.query().unwrap_or("-"));
		let hdrs = req.headers();

		for (key, value) in hdrs.iter() {
			info!(" -> {:?}: {:?}", key, value);
		}
		let res = match req.uri().path() {
			"/" => mk_response("home!".into()),
			_ => mk_response("not found".into()),
		};

		Box::pin(async {
			let frame_stream = req.into_body().map_frame(|frame| {
				let frame = if let Ok(data) = frame.into_data() {
					data.iter()
						.map(|byte| byte.to_ascii_uppercase())
						.collect::<Bytes>()
				} else {
					Bytes::new()
				};

				Frame::data(frame)
			});

			res
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
	let svc = Svc {};

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

