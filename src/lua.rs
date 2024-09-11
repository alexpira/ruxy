
use mlua::prelude::*;
use hyper::{Request,Response};
use log::{warn,error};

use crate::config::ConfigAction;
use crate::net::GatewayBody;
use crate::service::ServiceError;
use crate::filesys::load_file;

fn luatest() -> LuaResult<()> {
	let lua = Lua::new();
	
	let map_table = lua.create_table()?;
	map_table.set(1, "one")?;
	map_table.set("two", 2)?;

	lua.globals().set("map_table", map_table)?;

	lua.load(load_file("lua/test.lua").unwrap().unwrap()).exec()?;

	Ok(())
}

fn create_request(lua: &Lua, req: &Request<GatewayBody>) -> LuaResult<()> {
	let request = lua.create_table()?;
	request.set("method", req.method().as_str())?;

	request.set("path", req.uri().path())?;
	if let Some(q) = req.uri().query() {
		request.set("query", q)?;
	}
	if let Some(h) = req.uri().host() {
		request.set("host", h)?;
	}
	if let Some(p) = req.uri().port_u16() {
		request.set("port", p)?;
	}
	if let Some(s) = req.uri().scheme_str() {
		request.set("scheme", s)?;
	}

	lua.globals().set("request", request)?;
	Ok(())
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
	if let Err(e) = create_request(&lua, &req) {
		error!("{}Cannot set request into globals: {:?}", corr_id, e);
		return Ok(req);
	}
	if let Err(e) = lua.load(code).exec() {
		error!("{}Failed to run lua script: {:?}", corr_id, e);
		return Ok(req);
	}

	Ok(req)
}

pub fn apply_response_script(_action: &ConfigAction, res: Response<GatewayBody>, _corr_id: &str) -> Result<Response<GatewayBody>, ServiceError> {
	Ok(res)
}

