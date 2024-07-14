
use std::path::Path;
use std::{fs,error::Error};
use serde::Deserialize;
use std::net::{ToSocketAddrs, SocketAddr};

#[derive(Deserialize)]
pub struct Config {
	remote: String,
	bind: Option<String>,
}

impl Config {
	pub fn load(file: &str) -> Result<Self, Box<dyn Error>> {
		let content: String = fs::read_to_string(Path::new(file))?;
		//let cfg = content.parse::<toml::Table>()?;
		match toml::from_str(&content) {
			Ok(v) => Ok(v),
			Err(err) => Err(Box::from(format!("TOML parsing error: {}", err)))
		}
	}

	pub fn get_bind(&self) -> SocketAddr {
		if let Some(bind) = &self.bind {
			if let Ok(mut resolved) = bind.to_socket_addrs() {
				if let Some(top) = resolved.next() {
					return top;
				}
			}
		}
		([127, 0, 0, 1], 3000).into()
	}
}

