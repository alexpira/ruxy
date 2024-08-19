
use hyper_util::rt::tokio::TokioIo;
use log::warn;
use hyper::{Request,Response,StatusCode,Version,Uri};
use http::uri::{Scheme,Authority};
use std::str::FromStr;

use crate::net::{Stream,Sender,keepalive,GatewayBody};
use crate::service::{errmg,ServiceError};
use crate::config::{Config,ConfigAction};

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

	pub fn id(&self) -> &'static str {
		match self {
			HttpVersion::H1 => "h1",
			HttpVersion::H2 => "h2",
			HttpVersion::H2C => "h2c",
		}
	}

	pub fn adapt_request(&self, cfg: &Config, act: &ConfigAction, req: Request<GatewayBody>) -> Result<Request<GatewayBody>, ServiceError> {
		let src_ver = req.version();
		let need_tr = !self.matches(src_ver);
		let rewrite_host = act.get_rewrite_host();

		let mut urip = req.uri().clone().into_parts();

		let tgt_ver = if need_tr {
			self.to_version()
		} else {
			src_ver
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
					if let Ok(astr) = value.to_str() {
						if let Ok(auth) = Authority::from_str(astr) {
							urip.authority = Some(auth);
						}
					}
					continue;
				}
			}

			modified_request = modified_request.header(key, value);
		}
		if let Some(repl) = act.get_rewrite_host() {
			if self.h1() {
				modified_request = modified_request.header("host", repl.clone());
			}
			if self.h2() {
				if let Ok(auth) = Authority::from_str(repl.as_str()) {
					urip.authority = Some(auth);
				}
			}
		}

		if self.h2() {
			let ssl = if rewrite_host.is_some() {
				act.get_remote().ssl()
			} else {
				cfg.server_ssl()
			};

			urip.scheme = Some(if ssl { Scheme::HTTPS } else { Scheme::HTTP });
		}

		modified_request = modified_request.uri(Uri::from_parts(urip).unwrap());

		errmg!(modified_request.body(req.into_body()))
	}

	pub fn adapt_response(&self, _act: &ConfigAction, response: Response<GatewayBody>) -> Result<Response<GatewayBody>, ServiceError> {
		Ok(response)
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

