
use std::path::{Path,PathBuf};
use std::{fs,error::Error};
use serde::Deserialize;
use std::time::Duration;
use std::net::{ToSocketAddrs, SocketAddr};

#[derive(Deserialize)]
struct RawConfig {
	remote: String,
	bind: Option<String>,
	rewrite_host: Option<bool>,
	graceful_shutdown_timeout: Option<String>,
	cafile: Option<String>,
}

#[derive(Clone)]
pub struct Config {
	remote: (String, u16),
	remote_domain_raw: String,
	remote_ssl: bool,
	rewrite_host: Option<String>,
	bind: SocketAddr,
	graceful_shutdown_timeout: Duration,
	cafile: Option<PathBuf>,
}

impl Config {
	pub fn load(file: &str) -> Result<Self, Box<dyn Error>> {
		let content: String = fs::read_to_string(Path::new(file))?;
		let raw_cfg: RawConfig = match toml::from_str(&content) {
			Ok(v) => v,
			Err(err) => return Err(Box::from(format!("Config parsing error: {}", err)))
		};

		Ok(Config {
			remote: Self::parse_remote(&raw_cfg),
			remote_domain_raw: Self::parse_remote_domain(&raw_cfg),
			remote_ssl: Self::parse_remote_ssl(&raw_cfg),
			rewrite_host: Self::parse_rewrite_host(&raw_cfg),
			bind: Self::parse_bind(&raw_cfg),
			graceful_shutdown_timeout: Self::parse_graceful_shutdown_timeout(&raw_cfg),
			cafile: Self::parse_cafile(&raw_cfg),
		})
	}

	pub fn get_ca_file(&self) -> Option<PathBuf> {
		self.cafile.clone()
	}

	pub fn use_ssl(&self) -> bool {
		self.remote_ssl
	}

	pub fn get_domain(&self) -> String {
		self.remote_domain_raw.clone()
	}

	pub fn get_rewrite_host(&self) -> Option<String> {
		self.rewrite_host.clone()
	}

	pub fn get_graceful_shutdown_timeout(&self) -> Duration {
		self.graceful_shutdown_timeout
	}

	pub fn get_remote(&self) -> (String,u16) {
		self.remote.clone()
	}

	pub fn get_bind(&self) -> SocketAddr {
		self.bind
	}

	fn default_port(rc: &RawConfig) -> u16 {
		let def = rc.remote.to_lowercase();
		if def.starts_with("https://") { 443 } else { 80 }
	}

	fn extract_remote_host_def(rc: &RawConfig) -> String {
		let mut def = rc.remote.clone();
		if let Some(proto_split) = def.find("://") {
			def = def[proto_split+3..].to_string();
		}
		if let Some(path_split) = def.find("/") {
			def = def[..path_split].to_string();
		}
		if let Some(auth_split) = def.find("@") {
			def = def[auth_split+1..].to_string();
		}
		def
	}

	fn parse_remote_domain(rc: &RawConfig) -> String {
		Self::extract_remote_host_def(rc)
	}

	fn parse_rewrite_host(rc: &RawConfig) -> Option<String> {
		if !rc.rewrite_host.unwrap_or(false) {
			return None;
		}
		Some(Self::extract_remote_host_def(rc))
	}

	fn parse_remote(rc: &RawConfig) -> (String,u16) {
		let def = Self::extract_remote_host_def(rc);
		if let Some(port_split) = def.find(":") {
			let host = def[..port_split].to_string();
			let port = def[port_split+1..].parse::<u16>().unwrap_or(Self::default_port(rc));
			(host, port)
		} else {
			(def, Self::default_port(rc))
		}
	}

	fn parse_remote_ssl(rc: &RawConfig) -> bool {
		let def = rc.remote.to_lowercase();
		def.starts_with("https://")
	}

	fn parse_bind(rc: &RawConfig) -> SocketAddr {
		if let Some(bind) = &rc.bind {
			if let Ok(mut resolved) = bind.to_socket_addrs() {
				if let Some(top) = resolved.next() {
					return top;
				}
			}
		}
		([127, 0, 0, 1], 3000).into()
	}

	fn parse_graceful_shutdown_timeout(rc: &RawConfig) -> Duration {
		if let Some(def) = &rc.graceful_shutdown_timeout {
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

	fn parse_cafile(rc: &RawConfig) -> Option<PathBuf> {
		rc.cafile.as_ref().and_then(|v| Some(Path::new(v).to_path_buf()))
	}
}

