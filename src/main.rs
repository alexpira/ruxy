
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

		let res = match req.uri().path() {
			"/" => mk_response("home!".into()),
			_ => mk_response("not found".into()),
		};
		Box::pin(async { res })
	}
}


#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	let cfg = match config::Config::load("config.toml") {
		Ok(v) => v,
		Err(e) => panic!("{}", e)
	};

	let addr = cfg.get_bind();
	let svc = Svc {};

	let listener = TcpListener::bind(addr).await?;
	println!("Listening on http://{}", addr);
	loop {
		let (tcp, _) = listener.accept().await?;
		let io = TokioIo::new(tcp);
		let svc_clone = svc.clone();
		tokio::task::spawn(async move {
			if let Err(err) = http1::Builder::new()
				.timer(TokioTimer::new())
				.serve_connection(io, svc_clone)
				.await
			{
				println!("Error serving connection: {:?}", err);
			}
		});
	}
}
