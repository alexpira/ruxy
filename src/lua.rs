
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
			return Err(ServiceError::remap("Failed to convert from lua".to_string(), hyper::StatusCode::BAD_GATEWAY, e));
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

fn headers_to_lua<'a>(lua: &'a Lua, rheaders: &HeaderMap) -> LuaResult<mlua::Table<'a>> {
	let headers = lua.create_table()?;
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
			let mut count = 1; // LUA arrays start at 1 :-/
			for v in values {
				hlist.set(count, v)?;
				count += 1;
			}
			headers.set(key.as_str(), hlist)?;
		}
	}
	Ok(headers)
}

fn headers_from_lua(container: &mlua::Table, corr_id: &str) -> Result<HeaderMap,ServiceError> {
	let mut headers = HeaderMap::new();
	if let Some(lhdrs) = werr!(container.get::<&str, mlua::Value>("headers")).as_table() {
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
	Ok(headers)
}

fn body_from_lua(body: Option<mlua::Value>) -> Option<Vec<u8>> {
	body.and_then(|b| match b {
		mlua::Value::String(s) => {
			Some(s.as_bytes().to_vec())
		},
		_ => None,
	})
}
fn body_to_lua<'a>(lua: &'a mlua::Lua, container: &'a mlua::Table, body: hyper::body::Bytes) {
	let st = lua.create_string(&(*body)).expect("Failed to set body");
	container.set("body", st).expect("Failed to set body");
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

	let headers = headers_to_lua(lua, &req.headers)?;
	request.set("headers", headers)?;
	request.set("src", client_addr)?;

	Ok(request)
}

fn request_from_lua(lua: &mlua::Lua, mut parts: http::request::Parts, corr_id: &str) -> Result<(http::request::Parts, Option<Vec<u8>>), ServiceError> {
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

	let headers = headers_from_lua(&request, corr_id)?;

	let body = body_from_lua(request.get("body").ok());

	parts.method = method;
	parts.uri = uri;
	parts.headers = headers;

	Ok((parts, body))
}

fn response_to_lua<'a>(lua: &'a Lua, res: &http::response::Parts) -> LuaResult<mlua::Table<'a>> {
	let response = lua.create_table()?;

	response.set("status", res.status.as_u16())?;

	if let Some(reason) = res.extensions.get::<hyper::ext::ReasonPhrase>().and_then(|v| std::str::from_utf8(v.as_bytes()).ok()) {
		response.set("reason", reason)?;
	} else if let Some(creason) = res.status.canonical_reason() {
		response.set("reason", creason)?;
	}

	let headers = headers_to_lua(lua, &res.headers)?;
	response.set("headers", headers)?;

	Ok(response)
}

fn response_from_lua(lua: &mlua::Lua, mut parts: http::response::Parts, corr_id: &str) -> Result<(http::response::Parts, Option<Vec<u8>>), ServiceError> {
	let response: mlua::Table = werr!(lua.globals().get("response"));

	let status: u16 = werr!(response.get("status"));
	let reason: mlua::Value = werr!(response.get("reason"));

	let headers = headers_from_lua(&response, corr_id)?;

	parts.status = match http::StatusCode::from_u16(status) {
		Ok(v) => v,
		Err(_) => {
			error!("{}invalid response status code: {}", corr_id, status);
			parts.status
		}
	};
	parts.headers = headers;
	if let Some(reason) = reason.as_str() {
		let canonical = parts.status.canonical_reason().unwrap_or("");
		if canonical == reason {
			parts.extensions.remove::<hyper::ext::ReasonPhrase>();
		} else {
			if let Ok(v) = hyper::ext::ReasonPhrase::try_from(reason.as_bytes()) {
				parts.extensions.insert(v);
			} else {
				warn!("{}Invalid reason phrase: {}", corr_id, reason);
			}
		}
	}

	let body = body_from_lua(response.get("body").ok());

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
		body_to_lua(&lua, &lreq, bdata.clone().unwrap());
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
		body_to_lua(&lua, &lres, bdata.clone().unwrap());
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

pub enum HandleResult {
	Handled ( Response<GatewayBody> ),
	NotHandled ( Request<GatewayBody> ),
}

pub async fn apply_handle_request_script(action: &ConfigAction, req: Request<GatewayBody>, client_addr: &str, corr_id: &str) -> Result<HandleResult, ServiceError> {
	let script = match action.lua_handler_script() {
		Some(v) => v,
		None => return Ok(HandleResult::NotHandled(req)),
	};

	let code = match load_file(script) {
		Err(e) => {
			error!("{}cannot load {}: {:?}", corr_id, script, e);
			return Err(ServiceError::from("Error loading handler".to_string()));
		},
		Ok(v) => match v {
			None => {
				warn!("{}File '{}' not found", corr_id, script);
				return Err(ServiceError::from("Handler not found".to_string()));
			},
			Some(v) => v,
		}
	};

	let (parts, body) = req.into_parts();

	let bdata = body.into_bytes(corr_id).await?;

	let lua = Lua::new();

	if let Err(e) = lua.globals().set("corr_id", corr_id) {
		error!("{}Cannot set corr_id into globals: {:?}", corr_id, e);
		return Err(ServiceError::from("Handler interface error".to_string()));
	}
	let lreq = match request_to_lua(&lua, &parts, client_addr) {
		Ok(v) => v,
		Err(e) => {
			error!("{}Cannot set request into globals: {:?}", corr_id, e);
			return Err(ServiceError::from("Handler interface error".to_string()));
		},
	};

	body_to_lua(&lua, &lreq, bdata.clone());

	lua.globals().set("request", lreq).expect("Failed to set request");

	if let Err(e) = lua.load(code).exec() {
		error!("{}Failed to run lua script: {:?}", corr_id, e);
		return Err(ServiceError::from("Handler execution error".to_string()));
	}

	let (parts, _) = Response::new(GatewayBody::empty()).into_parts();
	let (parts,out_body) = response_from_lua(&lua, parts, corr_id)?;

	Ok(HandleResult::Handled(Response::from_parts(parts, out_body.and_then(|v| Some(GatewayBody::data(v.into()))).unwrap_or(GatewayBody::empty()))))
}


