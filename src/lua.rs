
use mlua::prelude::*;
use hyper::{Request,Response,header::{HeaderMap,HeaderName,HeaderValue}};
use log::{warn,error};
use std::str::FromStr;

use crate::config::ConfigAction;
use crate::net::GatewayBody;
use crate::service::ServiceError;
use crate::filesys::load_file;

macro_rules! werr {
	( $data: expr ) => { match $data {
		Ok(v) => v,
		Err(e) => {
			return Err(ServiceError::remap("Failed to convert request from lua".to_string(), hyper::StatusCode::BAD_GATEWAY, e));
		}
	} }
}

fn append_header(headers: &mut HeaderMap, key: String, value: mlua::String, corr_id: &str) -> mlua::Result<()> {
	let hk = match HeaderName::from_bytes(&key.clone().into_bytes()) {
		Ok(v) => v,
		Err(e) => {
			error!("{}Cannot convert lua header name '{}': {:?}", corr_id, key, e);
			return Err(mlua::Error::RuntimeError(format!("Cannot convert lua header name '{}': {:?}", key, e)));
		}
	};
	let hv = match HeaderValue::from_bytes(&value.as_bytes()) {
		Ok(v) => v,
		Err(e) => {
			error!("{}Cannot convert lua header value for '{}': {:?}", corr_id, key, e);
			return Err(mlua::Error::RuntimeError(format!("Cannot convert lua header value for '{}': {:?}", key, e)));
		}
	};

	headers.append(hk, hv);
	Ok(())
}

fn request_to_lua<'a>(lua: &'a Lua, req: &http::request::Parts, client_addr: &str) -> LuaResult<mlua::Table<'a>> {
let request = lua.create_table()?;
	request.set("method", req.method.as_str())?;

	let uri = lua.create_table()?;
	uri.set("path", req.uri.path())?;
	if let Some(q) = req.uri.query() {
		uri.set("query", q)?;
	}
	if let Some(h) = req.uri.host() {
		uri.set("host", h)?;
	}
	if let Some(p) = req.uri.port_u16() {
		uri.set("port", p)?;
	}
	if let Some(s) = req.uri.scheme_str() {
		uri.set("scheme", s)?;
	}
	request.set("uri", uri)?;

	let headers = lua.create_table()?;
	let rheaders = &req.headers;
	for key in rheaders.keys() {
		let mut values = Vec::new();
		for v in rheaders.get_all(key) {
			if let Ok(vs) = v.to_str() {
				values.push(vs);
			}
		}
		let sz = values.len();
		if sz == 1 {
			if let Some(only) = values.pop() {
				headers.set(key.as_str(), only)?;
			}
		} else if sz > 1 {
			let hlist = lua.create_table()?;
			let mut count = 0;
			for v in values {
				hlist.set(count, v)?;
				count += 1;
			}
			headers.set(key.as_str(), hlist)?;
		}
	}
	request.set("headers", headers)?;
	request.set("src", client_addr)?;

	Ok(request)
}

fn request_from_lua(lua: &mlua::Lua, mut parts: http::request::Parts, corr_id: &str) -> Result<(http::request::Parts, Option<Box<[u8]>>), ServiceError> {
	let request: mlua::Table = werr!(lua.globals().get("request"));

	let method: String = werr!(request.get("method"));
	let method = werr!(http::Method::from_bytes(method.as_bytes()));

	let uri: mlua::Table = werr!(request.get("uri"));
	let scheme: mlua::Value = werr!(uri.get("scheme"));
	let host: mlua::Value = werr!(uri.get("host"));
	let port: mlua::Value = werr!(uri.get("port"));
	let path: mlua::Value = werr!(uri.get("path"));
	let query: mlua::Value = werr!(uri.get("query"));

	let mut uri_parts = http::uri::Parts::default();

	uri_parts.scheme = scheme.as_str()
		.and_then(|v| http::uri::Scheme::from_str(v).ok())
		.or(parts.uri.scheme().cloned());

	uri_parts.authority = if let Some(hstr) = host.as_str() {
		let fullstr = if let Some(pvalue) = port.as_u32() {
			format!("{}:{}", hstr, pvalue)
		} else {
			hstr.to_string()
		};
		Some(werr!(http::uri::Authority::from_str(&fullstr)))
	} else {
		parts.uri.authority().cloned()
	};

	uri_parts.path_and_query = if let Some(pstr) = path.as_str() {
		let fullstr = if let Some(qvalue) = query.as_str() {
			if qvalue.is_empty() {
				pstr.to_string()
			} else {
				format!("{}?{}", pstr, qvalue)
			}
		} else {
			pstr.to_string()
		};
		Some(werr!(http::uri::PathAndQuery::from_str(&fullstr)))
	} else {
		parts.uri.path_and_query().cloned()
	};

	let uri = werr!(http::Uri::from_parts(uri_parts));

	let mut headers = HeaderMap::new();
	if let Some(lhdrs) = werr!(request.get::<&str, mlua::Value>("headers")).as_table() {
		werr!(lhdrs.for_each(|k: String, v: mlua::Value| {
			match v {
				mlua::Value::String(st) => append_header(&mut headers, k, st, corr_id),
				mlua::Value::Table(values) => {
					values.for_each(|_: mlua::Value, v: mlua::Value| {
						if let mlua::Value::String(st) = v {
							append_header(&mut headers, k.clone(), st, corr_id)
						} else {
							Ok(())
						}
					})
				},
				_ => Ok(()),
			}
		}));
	}

	let body: Option<Box<[u8]>> = request.get("body").ok();

	parts.method = method;
	parts.uri = uri;
	parts.headers = headers;

	Ok((parts, body))
}

fn response_to_lua<'a>(lua: &'a Lua, res: &http::response::Parts) -> LuaResult<mlua::Table<'a>> {
	let response = lua.create_table()?;

	response.set("status", res.status.as_u16())?;

	let headers = lua.create_table()?;
	let rheaders = &res.headers;
	for key in rheaders.keys() {
		let mut values = Vec::new();
		for v in rheaders.get_all(key) {
			if let Ok(vs) = v.to_str() {
				values.push(vs);
			}
		}
		let sz = values.len();
		if sz == 1 {
			if let Some(only) = values.pop() {
				headers.set(key.as_str(), only)?;
			}
		} else if sz > 1 {
			let hlist = lua.create_table()?;
			let mut count = 0;
			for v in values {
				hlist.set(count, v)?;
				count += 1;
			}
			headers.set(key.as_str(), hlist)?;
		}
	}
	response.set("headers", headers)?;

	Ok(response)
}

fn response_from_lua(lua: &mlua::Lua, mut parts: http::response::Parts, corr_id: &str) -> Result<(http::response::Parts, Option<Box<[u8]>>), ServiceError> {
	let response: mlua::Table = werr!(lua.globals().get("response"));

	let status: u16 = werr!(response.get("status"));

	let mut headers = HeaderMap::new();
	if let Some(lhdrs) = werr!(response.get::<&str, mlua::Value>("headers")).as_table() {
		werr!(lhdrs.for_each(|k: String, v: mlua::Value| {
			match v {
				mlua::Value::String(st) => append_header(&mut headers, k, st, corr_id),
				mlua::Value::Table(values) => {
					values.for_each(|_: mlua::Value, v: mlua::Value| {
						if let mlua::Value::String(st) = v {
							append_header(&mut headers, k.clone(), st, corr_id)
						} else {
							Ok(())
						}
					})
				},
				_ => Ok(()),
			}
		}));
	}

	let body: Option<Box<[u8]>> = response.get("body").ok();

	parts.status = match http::StatusCode::from_u16(status) {
		Ok(v) => v,
		Err(_) => {
			error!("{}invalid response status code: {}", corr_id, status);
			parts.status
		}
	};

	Ok((parts, body))
}

pub async fn apply_request_script(action: &ConfigAction, req: Request<GatewayBody>, client_addr: &str, corr_id: &str) -> Result<Request<GatewayBody>, ServiceError> {
	let script = match action.lua_request_script() {
		Some(v) => v,
		None => return Ok(req),
	};

	let code = match load_file(script) {
		Err(e) => {
			error!("{}cannot load {}: {:?}", corr_id, script, e);
			return Ok(req);
		},
		Ok(v) => match v {
			None => {
				warn!("{}File '{}' not found", corr_id, script);
				return Ok(req);
			},
			Some(v) => v,
		}
	};

	let (parts, body) = req.into_parts();

	let (bdata, body) = if action.lua_request_load_body() {
		(Some(body.into_bytes(corr_id).await?),None)
	} else {
		(None,Some(body))
	};

	let lua = Lua::new();

	if let Err(e) = lua.globals().set("corr_id", corr_id) {
		error!("{}Cannot set corr_id into globals: {:?}", corr_id, e);
		return Ok(Request::from_parts(parts,
			bdata.and_then(|v| Some(GatewayBody::data(v))).or(body).unwrap()
		));
	}
	let lreq = match request_to_lua(&lua, &parts, client_addr) {
		Ok(v) => v,
		Err(e) => {
			error!("{}Cannot set request into globals: {:?}", corr_id, e);
			return Ok(Request::from_parts(parts,
				bdata.and_then(|v| Some(GatewayBody::data(v))).or(body).unwrap()
			));
		},
	};

	let body_is_managed = if bdata.is_some() {
		let luabody = bdata.clone().unwrap();
		lreq.set("body", &(*luabody)).expect("Failed to set body");
		true
	} else { false };

	lua.globals().set("request", lreq).expect("Failed to set request");

	if let Err(e) = lua.load(code).exec() {
		error!("{}Failed to run lua script: {:?}", corr_id, e);
		return Ok(Request::from_parts(parts,
			bdata.and_then(|v| Some(GatewayBody::data(v))).or(body).unwrap()
		));
	}

	let (parts,out_body) = request_from_lua(&lua, parts, corr_id)?;

	if body_is_managed {
		Ok(Request::from_parts(parts, out_body.and_then(|v| Some(GatewayBody::data(v.into()))).unwrap_or(GatewayBody::empty())))
	} else {
		Ok(Request::from_parts(parts, body.unwrap()))
	}
}

pub async fn apply_response_script(action: &ConfigAction, res: Response<GatewayBody>, req: http::request::Parts, client_addr: &str, corr_id: &str) -> Result<Response<GatewayBody>, ServiceError> {
	let script = match action.lua_reply_script() {
		Some(v) => v,
		None => return Ok(res),
	};

	let code = match load_file(script) {
		Err(e) => {
			error!("{}cannot load {}: {:?}", corr_id, script, e);
			return Ok(res);
		},
		Ok(v) => match v {
			None => {
				warn!("{}File '{}' not found", corr_id, script);
				return Ok(res);
			},
			Some(v) => v,
		}
	};

	let (parts, body) = res.into_parts();

	let (bdata, body) = if action.lua_reply_load_body() {
		(Some(body.into_bytes(corr_id).await?),None)
	} else {
		(None,Some(body))
	};

	let lua = Lua::new();

	if let Err(e) = lua.globals().set("corr_id", corr_id) {
		error!("{}Cannot set corr_id into globals: {:?}", corr_id, e);
		return Ok(Response::from_parts(parts,
			bdata.and_then(|v| Some(GatewayBody::data(v))).or(body).unwrap()
		));
	}
	let lreq = match request_to_lua(&lua, &req, client_addr) {
		Ok(v) => v,
		Err(e) => {
			error!("{}Cannot set request into globals: {:?}", corr_id, e);
			return Ok(Response::from_parts(parts,
				bdata.and_then(|v| Some(GatewayBody::data(v))).or(body).unwrap()
			));
		},
	};
	let lres = match response_to_lua(&lua, &parts) {
		Ok(v) => v,
		Err(e) => {
			error!("{}Cannot set response into globals: {:?}", corr_id, e);
			return Ok(Response::from_parts(parts,
				bdata.and_then(|v| Some(GatewayBody::data(v))).or(body).unwrap()
			));
		},
	};

	let body_is_managed = if bdata.is_some() {
		let luabody = bdata.clone().unwrap();
		lres.set("body", &(*luabody)).expect("Failed to set body");
		true
	} else { false };

	lua.globals().set("request", lreq).expect("Failed to set request");
	lua.globals().set("response", lres).expect("Failed to set response");

	if let Err(e) = lua.load(code).exec() {
		error!("{}Failed to run lua script: {:?}", corr_id, e);
		return Ok(Response::from_parts(parts,
			bdata.and_then(|v| Some(GatewayBody::data(v))).or(body).unwrap()
		));
	}

	let (parts,out_body) = response_from_lua(&lua, parts, corr_id)?;

	if body_is_managed {
		Ok(Response::from_parts(parts, out_body.and_then(|v| Some(GatewayBody::data(v.into()))).unwrap_or(GatewayBody::empty())))
	} else {
		Ok(Response::from_parts(parts, body.unwrap()))
	}
}

