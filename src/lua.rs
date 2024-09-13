
use mlua::prelude::*;
use hyper::{Request,Response,body::Bytes};
use log::{warn,error};

use crate::config::ConfigAction;
use crate::net::GatewayBody;
use crate::service::ServiceError;
use crate::filesys::load_file;

#[tokio::main]
async fn load_body_bytes(mut body: GatewayBody, corr_id: &str) -> Result<Bytes,ServiceError> {
	body.load_bytes(corr_id).await
}


fn request_to_lua<'a>(lua: &'a Lua, req: &Request<GatewayBody>) -> LuaResult<mlua::Table<'a>> {
	let request = lua.create_table()?;
	request.set("method", req.method().as_str())?;

	let uri = lua.create_table()?;
	uri.set("path", req.uri().path())?;
	if let Some(q) = req.uri().query() {
		uri.set("query", q)?;
	}
	if let Some(h) = req.uri().host() {
		uri.set("host", h)?;
	}
	if let Some(p) = req.uri().port_u16() {
		uri.set("port", p)?;
	}
	if let Some(s) = req.uri().scheme_str() {
		uri.set("scheme", s)?;
	}
	request.set("uri", uri)?;

	let headers = lua.create_table()?;
	let rheaders = req.headers();
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

pub fn apply_request_script(action: &ConfigAction, req: Request<GatewayBody>, corr_id: &str) -> Result<Request<GatewayBody>, ServiceError> {
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

	let lua = Lua::new();

	if let Err(e) = lua.globals().set("corr_id", corr_id) {
		error!("{}Cannot set corr_id into globals: {:?}", corr_id, e);
		return Ok(req);
	}
	let lreq = match request_to_lua(&lua, &req) {
		Ok(v) => v,
		Err(e) => {
			error!("{}Cannot set request into globals: {:?}", corr_id, e);
			return Ok(req);
		},
	};

	let (parts, body) = req.into_parts();

	let body = load_body_bytes(body, corr_id)?;
	// let load_body = lua.create_function(|_, ()| -> LuaResult<()> { Ok(()) }).unwrap();
	lreq.set("body", &(*body));

	lua.globals().set("request", lreq).unwrap();

	let req = Request::from_parts(parts, GatewayBody::empty());

	if let Err(e) = lua.load(code).exec() {
		error!("{}Failed to run lua script: {:?}", corr_id, e);
		return Ok(req);
	}

	let request: mlua::Table = lua.globals().get("request").unwrap();
	let uri: mlua::Table = request.get("uri").unwrap();
	let path: mlua::String = uri.get("path").unwrap();
	println!("P: {:?}", path);

	Ok(req)
}

pub fn apply_response_script(_action: &ConfigAction, res: Response<GatewayBody>, _corr_id: &str) -> Result<Response<GatewayBody>, ServiceError> {
	Ok(res)
}

