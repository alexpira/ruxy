
use mlua::prelude::*;
use hyper::{Request,Response};
use log::{warn,error};
use std::str::FromStr;

use crate::config::ConfigAction;
use crate::net::GatewayBody;
use crate::service::ServiceError;
use crate::filesys::load_file;

fn request_to_lua<'a>(lua: &'a Lua, req: &http::request::Parts) -> LuaResult<mlua::Table<'a>> {
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

	Ok(request)
}

macro_rules! werr {
	( $data: expr ) => { match $data {
		Ok(v) => v,
		Err(e) => {
			return Err(ServiceError::remap("Failed to convert request from lua".to_string(), hyper::StatusCode::BAD_GATEWAY, e));
		}
	} }
}

fn request_from_lua(lua: &mlua::Lua, mut parts: http::request::Parts) -> Result<(http::request::Parts, Box<[u8]>), ServiceError> {
	let request: mlua::Table = werr!(lua.globals().get("request"));

	let method: String = werr!(request.get("method"));
	let method = werr!(hyper::Method::from_bytes(method.as_bytes()));

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
			format!("{}:{}", pstr, qvalue)
		} else {
			pstr.to_string()
		};
		Some(werr!(http::uri::PathAndQuery::from_str(&fullstr)))
	} else {
		parts.uri.path_and_query().cloned()
	};

	let uri = werr!(http::Uri::from_parts(uri_parts));

	let body: Box<[u8]> = werr!(request.get("body"));

	parts.method = method;
	parts.uri = uri;
	Ok((parts, body))
}

pub async fn apply_request_script(action: &ConfigAction, req: Request<GatewayBody>, corr_id: &str) -> Result<Request<GatewayBody>, ServiceError> {
	let script = "./lua/test.lua"; // TODO: load from action

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
	let bdata = body.into_bytes(corr_id).await?;

	let lua = Lua::new();

	if let Err(e) = lua.globals().set("corr_id", corr_id) {
		error!("{}Cannot set corr_id into globals: {:?}", corr_id, e);
		let req = Request::from_parts(parts, GatewayBody::data(bdata));
		return Ok(req);
	}
	let lreq = match request_to_lua(&lua, &parts) {
		Ok(v) => v,
		Err(e) => {
			error!("{}Cannot set request into globals: {:?}", corr_id, e);
			let req = Request::from_parts(parts, GatewayBody::data(bdata));
			return Ok(req);
		},
	};

	let luabody = bdata.clone();
	lreq.set("body", &(*luabody)).expect("Failed to set body");

	lua.globals().set("request", lreq).expect("Failed to set request");

	if let Err(e) = lua.load(code).exec() {
		error!("{}Failed to run lua script: {:?}", corr_id, e);
		let req = Request::from_parts(parts, GatewayBody::data(bdata));
		return Ok(req);
	}

	let (parts,body) = request_from_lua(&lua, parts)?;

	let req = Request::from_parts(parts, GatewayBody::data(body.into()));
	Ok(req)
}

pub fn apply_response_script(_action: &ConfigAction, res: Response<GatewayBody>, _corr_id: &str) -> Result<Response<GatewayBody>, ServiceError> {
	Ok(res)
}

