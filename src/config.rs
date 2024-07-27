
use std::path::{Path,PathBuf};
use std::{fs,env,error::Error,collections::HashMap};
use serde::Deserialize;
use std::time::Duration;
use std::net::{ToSocketAddrs, SocketAddr};
use hyper::{Method,Uri,header::HeaderMap};
use regex::Regex;
use log::warn;

#[derive(Clone)]
pub struct RemoteConfig {
	address: (String, u16),
	raw: String,
	domain: String,
	ssl: bool,
}

impl RemoteConfig {
	fn build(remote: &str) -> RemoteConfig {
		RemoteConfig {
			address: Self::parse_remote(&remote),
			raw: Self::extract_remote_host_def(&remote),
			domain: Self::parse_remote_domain(&remote),
			ssl: Self::parse_remote_ssl(&remote),
		}
	}

	pub fn address(&self) -> (String,u16) {
		self.address.clone()
	}
	pub fn raw(&self) -> String {
		self.raw.clone()
	}
	pub fn domain(&self) -> String {
		self.domain.clone()
	}
	pub fn ssl(&self) -> bool {
		self.ssl
	}

	fn extract_remote_host_def(remote: &str) -> String {
		let mut def = remote.to_string();
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

	fn parse_remote_domain(remote: &str) -> String {
		let def = Self::extract_remote_host_def(remote);
		if let Some(port_split) = def.find(":") {
			def[..port_split].to_string()
		} else {
			def
		}
	}

	fn default_port(remote: &str) -> u16 {
		let def = remote.to_lowercase();
		if def.starts_with("https://") { 443 } else { 80 }
	}

	fn parse_remote(remote: &str) -> (String,u16) {
		let def = Self::extract_remote_host_def(remote);
		if let Some(port_split) = def.find(":") {
			let host = def[..port_split].to_string();
			let port = def[port_split+1..].parse::<u16>().unwrap_or(Self::default_port(remote));
			(host, port)
		} else {
			(def, Self::default_port(remote))
		}
	}

	fn parse_remote_ssl(remote: &str) -> bool {
		let def = remote.to_lowercase();
		def.starts_with("https://")
	}
}

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
	headers: Option<HashMap<String,Regex>>,

	remote: Option<RemoteConfig>,
	rewrite_host: Option<bool>,
	log_headers: Option<bool>,
	log_request_body: Option<bool>,
	ssl_mode: Option<SslMode>,
	cafile: Option<PathBuf>,
}

impl ConfigFilter {
	fn parse_headers(v: &toml::Value) -> Option<HashMap<String,Regex>> {
		match v {
			toml::Value::Table(t) => {
				let mut parsed = HashMap::<String,Regex>::new();
				for k in t.keys() {
					if let Some(value) = t.get(k).and_then(|v| v.as_str()) {
						match Regex::new(value) {
							Ok(r) => { parsed.insert(k.to_lowercase(), r); },
							Err(e) => warn!("Invalid path regex in configuration \"{}\": {:?}", v, e),
						}
					}
				}
				if parsed.is_empty() {
					None
				} else {
					Some(parsed)
				}
			}
			_ => None
		}
	}

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
				headers: t.get("headers").and_then(|v| Self::parse_headers(v)),

				remote: t.get("remote").and_then(|v| v.as_str()).and_then(|v| Some(RemoteConfig::build(v))),
				rewrite_host: t.get("rewrite_host").and_then(|v| v.as_bool()),
				log_headers: t.get("log_headers").and_then(|v| v.as_bool()),
				log_request_body: t.get("log_request_body").and_then(|v| v.as_bool()),
				cafile: t.get("cafile").and_then(|v| v.as_str()).map(|v| Path::new(v).to_path_buf()),
				ssl_mode: t.get("ssl_mode").and_then(|v| v.as_str()).map(|v| v.to_string().into())
			}),
			_ => None,
		}
	}

	fn has_remote(&self) -> bool {
		self.remote.is_some()
	}

	fn get_remote(&self) -> Option<RemoteConfig> {
		self.remote.clone()
	}

	fn matches(&self, method: &Method, path: &Uri, headers: &HeaderMap) -> bool {
		if let Some(m) = self.method.as_ref() {
			if !m.eq_ignore_ascii_case(method.as_ref()) {
				return false;
			}
		}

		if let Some(rexp) = self.path.as_ref() {
			let pstr = path.path();
			if !rexp.is_match(&pstr) {
				return false;
			}
		}

		if let Some(hdrs) = self.headers.as_ref() {
			for k in hdrs.keys() {
				let mut ok = false;
				if let Some(rexp) = hdrs.get(k) {
					for hdr in headers.get_all(k) {
						if let Ok(hdrstr) = hdr.to_str() {
							if rexp.is_match(hdrstr) {
								ok = true;
								break;
							}
						}
					}
				}
				if !ok {
					return false;
				}
			}
		}

		true
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

impl<T> From<T> for SslMode where T: Into<String> {
	fn from(value: T) -> SslMode {
		let value = value.into().trim().to_lowercase();

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
}

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
#[allow(dead_code)] // TODO: http2 support is still work-in-progress
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

pub type SslData = (SslMode, HttpVersionMode, Option<PathBuf>);

#[derive(Clone)]
pub struct Config {
	remote: RemoteConfig,
	rewrite_host: bool,
	ssl_mode: SslMode,
	log_headers: bool,
	log_request_body: bool,
	cafile: Option<PathBuf>,

	bind: SocketAddr,
	graceful_shutdown_timeout: Duration,
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

		let remote = raw_cfg.remote.as_ref().expect("Missing main remote host in configuration");

		Ok(Config {
			remote: RemoteConfig::build(remote),
			rewrite_host: raw_cfg.rewrite_host.unwrap_or(false),
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

	fn get_filters<'a>(&'a self, method: &Method, path: &Uri, headers: &HeaderMap) -> Vec<&'a ConfigFilter> {
		let mut rv = Vec::new();
		for f in self.filters.iter() {
			if f.matches(method, path, headers) {
				rv.push(f);
			}
		}
		rv
	}

	pub fn get_ssl_mode(&self, method: &Method, path: &Uri, headers: &HeaderMap) -> SslMode {
		self.get_filters(method, path, headers)
			.iter().find(|v| v.ssl_mode.is_some())
			.and_then(|f| f.ssl_mode)
			.unwrap_or(self.ssl_mode)
	}

	pub fn get_ca_file(&self, method: &Method, path: &Uri, headers: &HeaderMap) -> Option<PathBuf> {
		self.get_filters(method, path, headers)
			.iter().find(|v| v.cafile.is_some())
			.and_then(|f| f.cafile.clone())
			.or(self.cafile.clone())
	}

	pub fn get_rewrite_host(&self, method: &Method, path: &Uri, headers: &HeaderMap) -> Option<String> {
		let rewrite = self.get_filters(method, path, headers)
			.iter().find(|v| v.rewrite_host.is_some())
			.and_then(|f| f.rewrite_host)
			.unwrap_or(self.rewrite_host);

		if !rewrite {
			return None;
		}

		Some( self.get_remote(method, path, headers).raw() )
	}

	pub fn get_graceful_shutdown_timeout(&self) -> Duration {
		self.graceful_shutdown_timeout
	}

	pub fn get_remote(&self, method: &Method, path: &Uri, headers: &HeaderMap) -> RemoteConfig {
		self.get_filters(method, path, headers)
			.iter().find(|v| v.has_remote())
			.and_then(|f| f.get_remote())
			.unwrap_or(self.remote.clone())
	}

	pub fn get_bind(&self) -> SocketAddr {
		self.bind
	}

	pub fn log_headers(&self, method: &Method, path: &Uri, headers: &HeaderMap) -> bool {
		self.get_filters(method, path, headers)
			.iter().find(|v| v.log_headers.is_some())
			.and_then(|f| f.log_headers)
			.unwrap_or(self.log_headers)
	}

	pub fn log_request_body(&self, method: &Method, path: &Uri, headers: &HeaderMap) -> bool {
		self.get_filters(method, path, headers)
			.iter().find(|v| v.log_request_body.is_some())
			.and_then(|f| f.log_request_body)
			.unwrap_or(self.log_request_body)
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
		rc.ssl_mode
			.as_ref()
			.unwrap_or(&"builtin".to_string())
			.into()
	}

	pub fn server_version(&self) -> HttpVersionMode {
		HttpVersionMode::V1 // TODO
	}
	pub fn client_version(&self, _method: &Method, _path: &Uri, _headers: &HeaderMap) -> HttpVersionMode {
		HttpVersionMode::V1 // TODO
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

