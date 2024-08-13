
use hyper_util::rt::tokio::TokioIo;
use log::warn;
use hyper::{Request,StatusCode};

use crate::net::{Stream,Sender,keepalive,GatewayBody};
use crate::service::{errmg,ServiceError};
use crate::config::ConfigAction;

#[derive(Clone,Copy)]
#[allow(dead_code)] // TODO: http2/3 support is still work-in-progress
pub enum HttpVersion { H1, H2, H2C /*, H3*/ }

impl HttpVersion {
	pub fn parse(st: &str) -> Option<Self> {
		match st.trim().to_lowercase().as_str() {
			"h1" => Some(HttpVersion::H1),
			"h2" => Some(HttpVersion::H2),
			"h2c" => Some(HttpVersion::H2C),
			_ => None,
		}
	}

	pub fn alpn_request(&self) -> Vec<Vec<u8>> {
		match &self {
			HttpVersion::H1 => vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()],
			HttpVersion::H2 => vec![b"h2".to_vec()],
			HttpVersion::H2C => vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()],
		}
	}

	pub async fn handshake(&self, io: TokioIo<Box<dyn Stream>>) -> Result<Box<dyn Sender>, ServiceError> {
		match self {
			HttpVersion::H1 => {
				let (sender, conn) = errmg!(hyper::client::conn::http1::handshake(io).await)?;
				keepalive!(conn);
				Ok(Box::new(sender))
			},
			HttpVersion::H2 => {
				let executor = hyper_util::rt::tokio::TokioExecutor::new();
				let (sender, conn) = errmg!(hyper::client::conn::http2::handshake(executor, io).await)?;
				keepalive!(conn);
				Ok(Box::new(sender))
			},
			HttpVersion::H2C => {
				let executor = hyper_util::rt::tokio::TokioExecutor::new();
				let (sender, conn) = errmg!(hyper::client::conn::http2::handshake(executor, io).await)?;
				// TODO: h2 handshake

				keepalive!(conn);
				Ok(Box::new(sender))
			},
		}
	}

	pub fn adapt(&self, cfg: &ConfigAction, req: Request<GatewayBody>) -> Result<Request<GatewayBody>, ServiceError> {
		let hdrs = req.headers();
		let mut modified_request = Request::builder()
			.method(req.method())
			.uri(req.uri());

		let mut host_done = false;
		for (key, value) in hdrs.iter() {
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
}

impl From<&str> for HttpVersion {
	fn from(st: &str) -> Self {
		HttpVersion::parse(st).unwrap_or(HttpVersion::H1)
	}
}

impl std::fmt::Display for HttpVersion {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			HttpVersion::H1 => formatter.write_str("V1"),
			HttpVersion::H2 => formatter.write_str("V2Direct"),
			HttpVersion::H2C => formatter.write_str("V2Handshake"),
		}
	}
}

