
use core::task::{Context,Poll};
use async_trait::async_trait;
use hyper::body::Frame;
use std::pin::Pin;

use hyper::body::Incoming;
use hyper::{Request, Response};
use log::{info};
use tokio::io::{AsyncRead,AsyncWrite};
use core::marker::Unpin;

#[async_trait]
pub trait Stream : AsyncRead + AsyncWrite + Unpin + Send { }
impl<T> Stream for T where T : AsyncRead + AsyncWrite + Unpin + Send { }

#[async_trait]
pub trait Sender : Send {
	async fn send(&mut self, req: Request<GatewayBody>) -> hyper::Result<Response<Incoming>>;
	async fn check(&mut self) -> bool;
}

#[async_trait]
impl Sender for hyper::client::conn::http1::SendRequest<GatewayBody> {
	async fn send(&mut self, req: Request<GatewayBody>) -> hyper::Result<Response<Incoming>> {
		self.send_request(req).await
	}
	async fn check(&mut self) -> bool {
		self.ready().await.is_ok()
	}
}
#[async_trait]
impl Sender for hyper::client::conn::http2::SendRequest<GatewayBody> {
	async fn send(&mut self, req: Request<GatewayBody>) -> hyper::Result<Response<Incoming>> {
		self.send_request(req).await
	}
	async fn check(&mut self) -> bool {
		self.ready().await.is_ok()
	}
}

pub struct GatewayBody {
	incoming: Option<Incoming>,
	frames: Vec<hyper::body::Bytes>,
	save_payload: bool,
	log_prefix: String,
}
impl GatewayBody {
	pub fn empty() -> GatewayBody {
		GatewayBody {
			incoming: None,
			frames: Vec::new(),
			save_payload: false,
			log_prefix: "".to_string(),
		}
	}
	pub fn wrap(inner: Incoming) -> GatewayBody {
		GatewayBody {
			incoming: Some(inner),
			frames: Vec::new(),
			save_payload: false,
			log_prefix: "".to_string(),
		}
	}

	pub fn log_payload(&mut self, value: bool, log_prefix: String) {
		self.save_payload = value;
		self.log_prefix = log_prefix;
	}

	fn add_frame(&mut self, frame: &hyper::body::Bytes) {
		if self.save_payload {
			self.frames.push(frame.clone());
		}
	}

	fn end(&self) {
		if self.save_payload {
			let log = String::from_utf8(self.frames.clone().concat()).unwrap_or("DECODE-ERROR".to_string());
			if log.is_empty() {
				info!("{}EMPTY BODY", self.log_prefix);
			} else {
				info!("{}BODY: {}", self.log_prefix, log);
			}
		}
	}
}

impl hyper::body::Body for GatewayBody {
	type Data = hyper::body::Bytes;
	type Error = hyper::Error;

	fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>,) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let me = &mut *self.as_mut().get_mut();

		let poll = match me.incoming.as_mut() {
			None => {
				me.end();
				return Poll::Ready(None);
			},
			Some(wrp) => {
				Pin::new(wrp).poll_frame(cx)
			},
		};
		let vopt = core::task::ready!(poll);

		if vopt.is_none() {
			me.end();
			return Poll::Ready(None);
		}
		match vopt.unwrap() {
			Err(e) => Poll::Ready(Some(Err(e))),
			Ok(frm) => {
				if let Some(data) = frm.data_ref() {
					me.add_frame(data);
				}
				Poll::Ready(Some(Ok(frm)))
			},
		}
	}

	fn is_end_stream(&self) -> bool {
		let rv = match &self.incoming {
			None => true,
			Some(wrp) => wrp.is_end_stream(),
		};
		if rv {
			self.end();
		}
		rv
	}
}

