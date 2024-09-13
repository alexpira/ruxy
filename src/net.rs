
use core::task::{Context,Poll};
use async_trait::async_trait;
use hyper::{Request, Response};
use hyper::body::{Bytes,Frame,Incoming};
use http_body_util::BodyExt;
use http::StatusCode;
use std::pin::Pin;
use base64::prelude::*;
use log::{info,warn};
use tokio::io::{AsyncRead,AsyncWrite};
use core::marker::Unpin;

use crate::service::ServiceError;

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

#[derive(PartialEq)]
enum BodyKind { EMPTY, INCOMING, BYTES }

pub struct GatewayBody {
	kind: BodyKind,
	incoming: Option<Incoming>,
	bytes: Option<Bytes>,
	bytes_read: bool,
	log_frames: Vec<Bytes>,
	log_payload: bool,
	log_prefix: String,
	max_payload_size: i64,
	current_payload_size: i64,
	transfer_started: bool,
}
impl GatewayBody {
	pub fn empty() -> GatewayBody {
		GatewayBody {
			kind: BodyKind::EMPTY,
			incoming: None,
			bytes: None,
			bytes_read: false,
			log_frames: Vec::new(),
			log_payload: false,
			log_prefix: "".to_string(),
			max_payload_size: 0,
			current_payload_size: 0,
			transfer_started: false,
		}
	}
	pub fn wrap(inner: Incoming) -> GatewayBody {
		GatewayBody {
			kind: BodyKind::INCOMING,
			incoming: Some(inner),
			bytes: None,
			bytes_read: false,
			log_frames: Vec::new(),
			log_payload: false,
			log_prefix: "".to_string(),
			max_payload_size: 0,
			current_payload_size: 0,
			transfer_started: false,
		}
	}

	pub fn log_payload(&mut self, value: bool, max_size: i64, log_prefix: String) {
		if self.transfer_started {
			warn!("{}:{} Cannot change parameters as transfer has already started", file!(), line!());
		} else {
			self.log_payload = value;
			self.log_prefix = log_prefix;
			self.max_payload_size = max_size;
		}
	}

	fn add_frame(&mut self, frame: &hyper::body::Bytes) {
		self.transfer_started = true;
		if self.log_payload {
			let newsz = self.current_payload_size + (frame.len() as i64);
			if newsz > self.max_payload_size {
				self.log_payload = false;
				warn!("{}{}:{} Hit max payload size", self.log_prefix, file!(), line!());
			} else {
				self.current_payload_size = newsz;
				self.log_frames.push(frame.clone());
			}
		}
	}

	fn end(&self) {
		if self.log_payload {
			let bdata = self.log_frames.clone().concat();
			let log = String::from_utf8(bdata).unwrap_or_else(|v| {
				format!("DECODE-ERROR at {}, B64={}", v.utf8_error().valid_up_to(), BASE64_STANDARD.encode(v.as_bytes()))
			});
			if log.is_empty() {
				info!("{}EMPTY BODY", self.log_prefix);
			} else {
				info!("{}BODY: {}", self.log_prefix, log);
			}
		}
	}

	pub async fn load_bytes(&mut self, corr_id: &str) -> Result<Bytes,ServiceError> {
		match self.kind {
			BodyKind::EMPTY => Ok(Bytes::from_static(&[])),
			BodyKind::BYTES => Ok(self.bytes.clone().unwrap_or(Bytes::from_static(&[]))),
			BodyKind::INCOMING => match self.incoming.take() {
				None => Ok(Bytes::from_static(&[])),
				Some(incoming) => {
					let coll = match incoming.collect().await {
						Ok(v) => v,
						Err(e) => {
							return Err(ServiceError::remap(format!("{}Failed to load body", corr_id), StatusCode::BAD_REQUEST, e));
						},
					};
					let bytes = coll.to_bytes();
					self.bytes = Some(bytes.clone());
					self.kind = BodyKind::BYTES;
					Ok(bytes)
				}
			}
		}
	}
}

impl hyper::body::Body for GatewayBody {
	type Data = hyper::body::Bytes;
	type Error = hyper::Error;

	fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>,) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let me = &mut *self.as_mut().get_mut();

		if me.kind == BodyKind::BYTES {
			if me.bytes_read {
				return Poll::Ready(None);
			} else if me.bytes.is_none() {
				return Poll::Ready(None);
			} else {
				let frame = Frame::data(me.bytes.clone().unwrap());
				me.bytes_read = true;
				return Poll::Ready(Some(Ok(frame)));
			}
		}

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
		if self.kind == BodyKind::BYTES {
			return self.bytes_read;
		}
	
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

macro_rules! keepalive {
	($arg: expr) => {
		tokio::task::spawn(async move {
			if let Err(err) = $arg.await {
				warn!("Connection failed: {:?}", err);
			}
		});
	}
}
pub(crate) use keepalive;

macro_rules! config_socket {
	($sock: expr) => {
		$sock.set_linger(Some(Duration::from_secs(0))).unwrap_or_else(|err| { warn!("{}:{} Failed to set SO_LINGER on socket: {:?}", file!(), line!(), err); () });
	}
}
pub(crate) use config_socket;

enum Direction { In, Out }

pub struct LoggingStream {
	wrapped: Box<dyn Stream + Send>
}
impl LoggingStream {
	pub fn wrap(t: impl Stream + 'static) -> Self {
		Self { wrapped: Box::new(t) }
	}
	fn dump(data: &[u8], dir: Direction) {
		let dirst = match dir {
			Direction::In => "<-",
			Direction::Out => "->"
		};
		for idx in (0..data.len()).step_by(16) {
			let mut bline = String::with_capacity(48);
			let mut cline = String::with_capacity(16);
			for inidx in 0..16 {
				let totidx = idx+inidx;
				if totidx < data.len() {
					let ch = data[totidx];
					bline.push_str(format!("{:02x} ", ch).as_str());
					if ch.is_ascii_graphic() {
						cline.push_str(std::str::from_utf8(&[ch]).unwrap_or("."));
					} else {
						cline.push_str(".");
					}
				} else {
					bline.push_str("   ");
					cline.push_str(" ");
				}
			}
			info!("{} {}{}", dirst, bline, cline);
		}
	}
}
impl AsyncRead for LoggingStream {
	fn poll_read(mut self: Pin<&mut Self>, ctx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<Result<(), std::io::Error>> {
		let pos = buf.filled().len();
		let result = Pin::new(&mut self.wrapped).poll_read(ctx, buf);
		if buf.filled().len() > pos {
			let data = &buf.filled()[pos..];
			Self::dump(data, Direction::In);
		}
		result
	}
}
impl AsyncWrite for LoggingStream {
	fn poll_write(mut self: Pin<&mut Self>, ctx: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
		Self::dump(data, Direction::Out);
		Pin::new(&mut self.wrapped).poll_write(ctx, data)
	}
	fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut std::task::Context<'_>) -> Poll<Result<(), std::io::Error>> {
		Pin::new(&mut self.wrapped).poll_flush(ctx)
	}
	fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut std::task::Context<'_>) -> Poll<Result<(), std::io::Error>> {
		Pin::new(&mut self.wrapped).poll_shutdown(ctx)
	}
}
impl Unpin for LoggingStream { }


