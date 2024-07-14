
use std::path::Path;
use std::{fs,error::Error};
use serde::Deserialize;
use std::time::Duration;
use std::net::{ToSocketAddrs, SocketAddr};

#[derive(Deserialize)]
pub struct Config {
	remote: String,
	bind: Option<String>,
	graceful_shutdown_timeout: Option<String>,
}

impl Config {
	pub fn load(file: &str) -> Result<Self, Box<dyn Error>> {
		let content: String = fs::read_to_string(Path::new(file))?;
		//let cfg = content.parse::<toml::Table>()?;
		match toml::from_str(&content) {
			Ok(v) => Ok(v),
			Err(err) => Err(Box::from(format!("Config parsing error: {}", err)))
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

	pub fn get_graceful_shutdown_timeout(&self) -> Duration {
		if let Some(def) = &self.graceful_shutdown_timeout {
			let mut pars = def.trim().to_lowercase();
			let mut mult: u64 = 1000;
			if pars.ends_with("sec") {
				pars.pop();
				pars.pop();
				pars.pop();
			} else if pars.ends_with("ms") {
				pars.pop();
				pars.pop();
				mult = 1;
			} else if pars.ends_with("min") {
				pars.pop();
				pars.pop();
				pars.pop();
				mult = 60000;
			}
			let pars = pars.trim().to_string();
			if let Ok(v) = pars.parse::<u64>() {
				return Duration::from_millis(v * mult);
			}
		}
		Duration::from_secs(10)
	}
}

