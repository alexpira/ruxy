
use mlua::prelude::*;
use hyper::{Request,Response};
use log::{warn,error};

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

	let request: mlua::Table = lua.globals().get("request").unwrap();
	let uri: mlua::Table = request.get("uri").unwrap();
	let path: mlua::String = uri.get("path").unwrap();
	println!("P: {:?}", path);

	let req = Request::from_parts(parts, GatewayBody::data(bdata));
	Ok(req)
}

pub fn apply_response_script(_action: &ConfigAction, res: Response<GatewayBody>, _corr_id: &str) -> Result<Response<GatewayBody>, ServiceError> {
	Ok(res)
}

