
use std::path::{Path,PathBuf};
use std::{fs,error::Error};
use serde::Deserialize;
use std::time::Duration;
use std::net::{ToSocketAddrs, SocketAddr};
use hyper::{Method,Uri};
use regex::Regex;
use std::env;
use log::warn;

#[derive(Deserialize)]
struct RawConfig {
	remote: Option<String>,
	bind: Option<String>,
	rewrite_host: Option<bool>,
	graceful_shutdown_timeout: Option<String>,
	ssl_mode: Option<String>,
	cafile: Option<String>,
	log_headers: Option<bool>,
	log_request_body: Option<bool>,
	server_ssl_trust: Option<String>,
	server_ssl_key: Option<String>,
	filters: Option<toml::Table>,
}

#[derive(Clone)]
struct ConfigFilter {
	path: Option<Regex>,
	method: Option<String>,
	log_headers: Option<bool>,
	log_request_body: Option<bool>,
}

impl ConfigFilter {
	fn parse(v: &toml::Value) -> Option<ConfigFilter> {
		match v {
			toml::Value::Table(t) => Some(ConfigFilter {
				path: t.get("path")
					.and_then(|v| v.as_str())
					.and_then(|v| match Regex::new(v) {
						Ok(r) => Some(r),
						Err(e) => {
							warn!("Invalid path regex in configuration \"{}\": {:?}", v, e);
							None
						},
					}),
				method: t.get("method").and_then(|v| v.as_str()).and_then(|v| Some(v.to_string())),
				log_headers: t.get("log_headers").and_then(|v| v.as_bool()),
				log_request_body: t.get("log_request_body").and_then(|v| v.as_bool()),
			}),
			_ => None,
		}
	}

	fn matches(&self, method: &Method, path: &Uri) -> bool {
		if let Some(m) = self.method.as_ref() {
			if !m.eq_ignore_ascii_case(method.as_ref()) {
				return false;
			}
		}

		match self.path.as_ref() {
			None => true,
			Some(rexp) => {
				let pstr = path.path();
				rexp.is_match(&pstr)
			}
		}
	}
}

impl RawConfig {
	fn from_env() -> RawConfig {
		RawConfig {
			remote: Self::env_str("REMOTE"),
			bind: Self::env_str("BIND"),
			rewrite_host: Self::env_bool("REWRITE_HOST"),
			graceful_shutdown_timeout: Self::env_str("GRACEFUL_SHUTDOWN_TIMEOUT"),
			ssl_mode: Self::env_str("SSL_MODE"),
			cafile: Self::env_str("CAFILE"),
			log_headers: Self::env_bool("LOG_HEADERS"),
			log_request_body: Self::env_bool("LOG_REQUEST_BODY"),
			server_ssl_trust: Self::env_str("SERVER_SSL_TRUST"),
			server_ssl_key: Self::env_str("SERVER_SSL_KEY"),
			filters: None,
		}
	}

	fn env_str(name: &str) -> Option<String> {
		match env::var(name) {
			Ok(v) => Some(v),
			Err(_) => None
		}
	}

	fn env_bool(name: &str) -> Option<bool> {
		Self::env_str(name).and_then(|v| {
			let vi = v.to_lowercase();
			let vi = vi.trim();
			if "true" == vi || "1" == vi {
				Some(true)
			} else if "false" == vi || "0" == vi {
				Some(false)
			} else {
				None
			}
		})
	}

	fn merge(&mut self, other: RawConfig) {
		self.remote = self.remote.take().or(other.remote);
		self.bind = self.bind.take().or(other.bind);
		self.rewrite_host = self.rewrite_host.take().or(other.rewrite_host);
		self.graceful_shutdown_timeout = self.graceful_shutdown_timeout.take().or(other.graceful_shutdown_timeout);
		self.ssl_mode = self.ssl_mode.take().or(other.ssl_mode);
		self.cafile = self.cafile.take().or(other.cafile);
		self.log_headers = self.log_headers.take().or(other.log_headers);
		self.log_request_body = self.log_request_body.take().or(other.log_request_body);
		self.server_ssl_trust = self.server_ssl_trust.take().or(other.server_ssl_trust);
		self.server_ssl_key = self.server_ssl_key.take().or(other.server_ssl_key);
		self.filters = self.filters.take().or(other.filters);
	}

	fn get_filters(&self) -> Vec<ConfigFilter> {
		if self.filters.is_none() {
			return Vec::new();
		}

		let mut rv = Vec::new();
		for v in self.filters.as_ref().unwrap().values() {
			if let Some(cf) = ConfigFilter::parse(v) {
				rv.push(cf);
			}
		}
		return rv;
	}
}

#[derive(Clone,Copy)]
pub enum SslMode { Builtin, File, OS, Dangerous }

impl std::fmt::Display for SslMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			SslMode::Builtin => formatter.write_str("Builtin"),
			SslMode::OS => formatter.write_str("OS"),
			SslMode::File => formatter.write_str("File"),
			SslMode::Dangerous => formatter.write_str("Dangerous"),
		}
    }
}

#[derive(Clone,Copy)]
pub enum HttpVersionMode { V1, V2Direct, V2Handshake }

impl std::fmt::Display for HttpVersionMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			HttpVersionMode::V1 => formatter.write_str("V1"),
			HttpVersionMode::V2Direct => formatter.write_str("V2Direct"),
			HttpVersionMode::V2Handshake => formatter.write_str("V2Handshake"),
		}
    }
}


#[derive(Clone)]
pub struct Config {
	remote: (String, u16),
	remote_domain_raw: String,
	remote_ssl: bool,
	rewrite_host: Option<String>,
	bind: SocketAddr,
	graceful_shutdown_timeout: Duration,
	ssl_mode: SslMode,
	cafile: Option<PathBuf>,
	log_headers: bool,
	log_request_body: bool,
	server_ssl_trust: Option<PathBuf>,
	server_ssl_key: Option<PathBuf>,
	filters: Vec<ConfigFilter>,
}

impl Config {
	pub fn load(file: &str) -> Result<Self, Box<dyn Error>> {
		let mut raw_cfg = RawConfig::from_env();
		let cfg_file = Path::new(file);
		if cfg_file.exists() {
			let content: String = fs::read_to_string(Path::new(file))?;
			let file_cfg: RawConfig = match toml::from_str(&content) {
				Ok(v) => v,
				Err(err) => return Err(Box::from(format!("Config parsing error: {}", err)))
			};
			raw_cfg.merge(file_cfg);
		}

		Ok(Config {
			remote: Self::parse_remote(&raw_cfg),
			remote_domain_raw: Self::parse_remote_domain(&raw_cfg),
			remote_ssl: Self::parse_remote_ssl(&raw_cfg),
			rewrite_host: Self::parse_rewrite_host(&raw_cfg),
			bind: Self::parse_bind(&raw_cfg),
			graceful_shutdown_timeout: Self::parse_graceful_shutdown_timeout(&raw_cfg),
			ssl_mode: Self::parse_ssl_mode(&raw_cfg),
			cafile: Self::parse_file(&raw_cfg.cafile),
			log_headers: raw_cfg.log_headers.unwrap_or(false),
			log_request_body: raw_cfg.log_request_body.unwrap_or(false),
			server_ssl_trust: Self::parse_file(&raw_cfg.server_ssl_trust),
			server_ssl_key: Self::parse_file(&raw_cfg.server_ssl_key),
			filters: raw_cfg.get_filters(),
		})
	}

	pub fn get_ssl_mode(&self) -> SslMode {
		self.ssl_mode
	}

	pub fn get_ca_file(&self) -> Option<PathBuf> {
		self.cafile.clone()
	}

	pub fn client_use_ssl(&self) -> bool {
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

	pub fn log_headers(&self, method: &Method, path: &Uri) -> bool {
		for f in self.filters.iter() {
			if f.matches(method, path) {
				if let Some(v) = f.log_headers {
					return v;
				}
			}
		}
		self.log_headers
	}

	pub fn log_request_body(&self, method: &Method, path: &Uri) -> bool {
		for f in self.filters.iter() {
			if f.matches(method, path) {
				if let Some(v) = f.log_request_body {
					return v;
				}
			}
		}
		self.log_request_body
	}

	fn default_port(rc: &RawConfig) -> u16 {
		let def = rc.remote.clone().expect("Missing remote host in configuration").to_lowercase();
		if def.starts_with("https://") { 443 } else { 80 }
	}

	fn extract_remote_host_def(rc: &RawConfig) -> String {
		let mut def = rc.remote.clone().expect("Missing remote host in configuration");
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
		let def = Self::extract_remote_host_def(rc);
		if let Some(port_split) = def.find(":") {
			def[..port_split].to_string()
		} else {
			def
		}
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
		let def = rc.remote.clone().expect("Missing remote host in configuration").to_lowercase();
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

	fn parse_file(value: &Option<String>) -> Option<PathBuf> {
		value.as_ref().and_then(|v| Some(Path::new(v).to_path_buf()))
	}

	fn parse_ssl_mode(rc: &RawConfig) -> SslMode {
		let value = rc.ssl_mode
			.clone()
			.unwrap_or("builtin".to_string())
			.trim()
			.to_lowercase();

		match value.as_str() {
			"unverified" => SslMode::Dangerous,
			"dangerous" => SslMode::Dangerous,
			"ca" => SslMode::File,
			"cafile" => SslMode::File,
			"file" => SslMode::File,
			"os" => SslMode::OS,
			"builtin" => SslMode::Builtin,
			_ => {
				warn!("Invalid ssl_mode in config file, falling back to builtin");
				SslMode::Builtin
			},
		}
	}

	pub fn server_version(&self) -> HttpVersionMode {
		HttpVersionMode::V1
	}
	pub fn client_version(&self) -> HttpVersionMode {
		HttpVersionMode::V1
	}

	pub fn server_ssl(&self) -> bool {
		self.server_ssl_trust.is_some() && self.server_ssl_key.is_some()
	}

	pub fn get_server_ssl_cafile(&self) -> Option<PathBuf> {
		self.server_ssl_trust.clone()
	}

	pub fn get_server_ssl_keyfile(&self) -> Option<PathBuf> {
		self.server_ssl_key.clone()
	}
}

