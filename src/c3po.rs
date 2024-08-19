
use hyper_util::rt::tokio::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper::{Request,Response,StatusCode,Version,Uri};
use hyper::server::conn::http1;
use hyper::upgrade::Upgraded;
use http::uri::{Scheme,Authority};
use std::str::FromStr;
use log::{debug,warn};

use crate::net::{Stream,Sender,keepalive,GatewayBody};
use crate::service::{GatewayService,errmg,ServiceError};
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

    async fn upgrade_1to2(target: String, mut sender: hyper::client::conn::http1::SendRequest<GatewayBody>) -> Result<Upgraded, ServiceError> {
        let req = errmg!(Request::builder()
			.method("HEAD")
            .uri("/")
            .header(hyper::header::HOST, target)
            .header(hyper::header::CONNECTION, "Upgrade, HTTP2-Settings")
            .header(hyper::header::UPGRADE, "h2c")
			.header("HTTP2-Settings", "AAMAAABkAAQAoAAAAAIAAAAA")
            .body(GatewayBody::empty()))?;

        let res = errmg!(sender.send_request(req).await)?;

        if res.status() != StatusCode::SWITCHING_PROTOCOLS {
            Err(format!("h2c upgrade failed, status: {}", res.status()).into())
        } else {
            errmg!(hyper::upgrade::on(res).await)
        }
    }

	pub async fn handshake(&self, target: String, io: TokioIo<Box<dyn Stream>>) -> Result<Box<dyn Sender>, ServiceError> {
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
				let (sender, conn) = errmg!(hyper::client::conn::http1::handshake(io).await)?;
				keepalive!(conn.with_upgrades());

                let upgraded = Self::upgrade_1to2(target, sender).await?;

				let executor = hyper_util::rt::tokio::TokioExecutor::new();
				let (upgsender, _conn) = errmg!(hyper::client::conn::http2::handshake(executor, upgraded).await)?;

				Ok(Box::new(upgsender))
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

	pub fn serve(&self, io: TokioIo<Box<dyn Stream>>, svc: GatewayService, graceful: &GracefulShutdown) {
		let conn = http1::Builder::new()
				.timer(TokioTimer::new())
				.serve_connection(io, svc);
		let fut = graceful.watch(conn);
		tokio::task::spawn(async move {
			if let Err(err) = fut.await {
				debug!("Client connection terminated {:?}", err);
			}
		});
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

