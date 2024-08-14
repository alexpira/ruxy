
use hyper_util::rt::tokio::TokioIo;
use log::warn;
use hyper::{Request,StatusCode,Version,Uri};
use http::uri::Authority;

use crate::net::{Stream,Sender,keepalive,GatewayBody};
use crate::service::{errmg,ServiceError};
use crate::config::ConfigAction;

#[derive(Clone,Copy,PartialEq)]
pub enum HttpVersion { H1, H2, H2C /*, TODO: H3*/ }

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

	fn h1(&self) -> bool {
		*self == HttpVersion::H1
	}
	fn h2(&self) -> bool {
		*self == HttpVersion::H2 || *self == HttpVersion::H2C
	}

	fn matches(&self, ver: Version) -> bool {
		match self {
			HttpVersion::H1 => {
				ver == Version::HTTP_09 ||
				ver == Version::HTTP_10 ||
				ver == Version::HTTP_11
			},
			HttpVersion::H2 => ver == Version::HTTP_2,
			HttpVersion::H2C => ver == Version::HTTP_2,
		}
	}

	fn to_version(&self) -> Version {
		match self {
			HttpVersion::H1 => Version::HTTP_11,
			HttpVersion::H2 => Version::HTTP_2,
			HttpVersion::H2C => Version::HTTP_2,
		}
	}

	pub fn adapt(&self, cfg: &ConfigAction, req: Request<GatewayBody>) -> Result<Request<GatewayBody>, ServiceError> {
		let src_ver = req.version();
		let need_tr = !self.matches(src_ver);
		let rewrite_host = cfg.get_rewrite_host();

		let mut urip = req.uri().clone().into_parts();

		let tgt_ver = if need_tr {
			src_ver
		} else {
			self.to_version()
		};
		let hdrs = req.headers();

		let mut modified_request = Request::builder()
			.method(req.method())
			.version(tgt_ver);

		for (key, value) in hdrs.iter() {
			if key == "host" {
				if rewrite_host.is_some() {
					continue;
				}
				if self.h2() {
					modified_request = modified_request.header(":authority", value);
					if let Ok(astr) = value.to_str() {
//						urip.authority = Some(Authority::from(astr));
					}
					continue;
				}
			}
			if key == ":method" && self.h1() {
//				modified_request.method(value);
				continue;
			}

			modified_request = modified_request.header(key, value);
		}
		if let Some(repl) = cfg.get_rewrite_host() {
			modified_request = modified_request.header(
				if self.h1() { "host" } else { ":authority" },
				repl);
			if self.h2() {
//				urip.authority = Authority::from_str(repl);
			}
		}

		modified_request = modified_request.uri(Uri::from_parts(urip).unwrap());

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

