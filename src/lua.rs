
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

pub fn apply_request_script(action: &ConfigAction, mut req: Request<GatewayBody>, corr_id: &str) -> Result<Request<GatewayBody>, ServiceError> {
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
	if let Err(e) = lua.load(code).exec() {
		error!("{}Failed to run lua script: {:?}", corr_id, e);
		return Ok(req);
	}

	Ok(req)
}

pub fn apply_response_script(_action: &ConfigAction, mut res: Response<GatewayBody>, _corr_id: &str) -> Result<Response<GatewayBody>, ServiceError> {
	Ok(res)
}

