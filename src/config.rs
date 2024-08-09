
use std::path::{Path,PathBuf};
use std::{env,error::Error,collections::HashMap};
use serde::Deserialize;
use std::time::Duration;
use std::net::{ToSocketAddrs, SocketAddr};
use hyper::{Method,Uri,header::HeaderMap,StatusCode};
use regex::Regex;
use log::{LevelFilter,info,warn};

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

#[derive(Clone)]
struct ConfigFilter {
	path: Option<Regex>,
	method: Option<String>,
	headers: Option<HashMap<String,Regex>>,
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

			}),
			_ => None,
		}
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

#[derive(Clone,Default)]
pub struct ConfigAction {
	remote: Option<RemoteConfig>,
	rewrite_host: Option<bool>,
	log: Option<bool>,
	log_headers: Option<bool>,
	log_request_body: Option<bool>,
	max_request_log_size: Option<i64>,
	log_reply_body: Option<bool>,
	max_reply_log_size: Option<i64>,
	ssl_mode: Option<SslMode>,
	cafile: Option<PathBuf>,
}

impl ConfigAction {
	fn parse(v: &toml::Value) -> Option<ConfigAction> {
		match v {
			toml::Value::Table(t) => Some(ConfigAction {
				remote: t.get("remote").and_then(|v| v.as_str()).and_then(|v| Some(RemoteConfig::build(v))),
				rewrite_host: t.get("rewrite_host").and_then(|v| v.as_bool()),
				log: t.get("log").and_then(|v| v.as_bool()),
				log_headers: t.get("log_headers").and_then(|v| v.as_bool()),
				log_request_body: t.get("log_request_body").and_then(|v| v.as_bool()),
				max_request_log_size: t.get("max_request_log_size").and_then(|v| v.as_integer()),
				log_reply_body: t.get("log_reply_body").and_then(|v| v.as_bool()),
				max_reply_log_size: t.get("max_reply_log_size").and_then(|v| v.as_integer()),
				cafile: t.get("cafile").and_then(|v| v.as_str()).map(|v| Path::new(v).to_path_buf()),
				ssl_mode: t.get("ssl_mode").and_then(|v| v.as_str()).map(|v| v.to_string().into())
			}),
			_ => None,
		}
	}

	fn merge(&mut self, other: &ConfigAction) {
		self.remote = self.remote.take().or(other.remote.clone());
		self.rewrite_host = self.rewrite_host.take().or(other.rewrite_host);
		self.log = self.log.take().or(other.log);
		self.log_headers = self.log_headers.take().or(other.log_headers);
		self.log_request_body = self.log_request_body.take().or(other.log_request_body);
		self.max_request_log_size = self.max_request_log_size.take().or(other.max_request_log_size);
		self.log_reply_body = self.log_reply_body.take().or(other.log_reply_body);
		self.max_reply_log_size = self.max_reply_log_size.take().or(other.max_reply_log_size);
		self.cafile = self.cafile.take().or(other.cafile.clone());
		self.ssl_mode = self.ssl_mode.take().or(other.ssl_mode);
	}

	pub fn get_ssl_mode(&self) -> SslMode {
		self.ssl_mode.unwrap_or(SslMode::Builtin)
	}

	pub fn get_ca_file(&self) -> Option<PathBuf> {
		self.cafile.clone()
	}

	pub fn get_rewrite_host(&self) -> Option<String> {
		let rewrite = self.rewrite_host.unwrap_or(false);

		if !rewrite {
			return None;
		}

		Some( self.remote.as_ref().unwrap().raw() )
	}

	pub fn get_remote(&self) -> RemoteConfig {
		self.remote.clone().unwrap()
	}

	pub fn log(&self) -> bool {
		self.log.unwrap_or(true)
	}

	pub fn log_headers(&self) -> bool {
		self.log_headers.unwrap_or(false)
	}

	pub fn log_request_body(&self) -> bool {
		self.log_request_body.unwrap_or(false)
	}

	pub fn max_request_log_size(&self) -> i64 {
		self.max_request_log_size.unwrap_or(256 * 1024)
	}

	pub fn log_reply_body(&self) -> bool {
		self.log_reply_body.unwrap_or(false)
	}

	pub fn max_reply_log_size(&self) -> i64 {
		self.max_reply_log_size.unwrap_or(256 * 1024)
	}

	pub fn client_version(&self) -> HttpVersionMode {
		HttpVersionMode::V1 // TODO
	}
}

#[derive(Clone)]
struct ConfigRule {
	name: String,
	filters: Vec<String>,
	actions: Vec<String>,
	enabled: bool,
	disable_on: Option<Regex>,
	keep_while: Option<Regex>,
	probability: Option<f64>,
	max_life: Option<u64>,
	consumed: u64,
}

impl ConfigRule {
	fn load_vec(t: &toml::Table, str_key: &str, list_key: &str) -> Vec<String> {
		let mut data = Vec::new();
		if let Some(single) = t.get(str_key).and_then(|v| v.as_str()) {
			data.push(single.to_string());
		}
		if let Some(list) = t.get(list_key).and_then(|v| v.as_array()) {
			for v in list {
				if let Some(vstr) = v.as_str() {
					data.push(vstr.to_string());
				}
			}
		}
		data
	}

	fn parse(name: String, v: &toml::Value) -> Option<ConfigRule> {
		match v {
			toml::Value::Table(t) => Some(ConfigRule {
				name: name,
				filters: Self::load_vec(t, "filter", "filters"),
				actions: Self::load_vec(t, "action", "actions"),
				enabled: t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
				probability: t.get("probability").and_then(|v| v.as_float()),
				disable_on: t.get("disable_on")
					.and_then(|v| v.as_str())
					.and_then(|v| match Regex::new(v) {
						Ok(r) => Some(r),
						Err(e) => {
							warn!("Invalid disable_on regex in configuration \"{}\": {:?}", v, e);
							None
						},
					}),
				keep_while: t.get("keep_while")
					.and_then(|v| v.as_str())
					.and_then(|v| match Regex::new(v) {
						Ok(r) => Some(r),
						Err(e) => {
							warn!("Invalid keep_while regex in configuration \"{}\": {:?}", v, e);
							None
						},
					}),
				max_life: t.get("max_life").and_then(|v| v.as_integer()).and_then(|v| Some(v as u64)),
				consumed: 0u64,
			}),
			_ => None,
		}
	}

	fn matches(&self, filters: &HashMap<String,ConfigFilter>, method: &Method, path: &Uri, headers: &HeaderMap) -> bool {
		if !self.enabled {
			return false;
		}
		if self.actions.is_empty() {
			return false;
		}

		let mut rv = self.filters.is_empty();
		if ! rv {
			for f in &self.filters {
				if let Some(cfilter) = filters.get(f) {
					if cfilter.matches(method, path, headers) {
						rv = true;
						break;
					}
				}
			}
		}

		if rv {
			if let Some(prob) = self.probability {
				if crate::random::gen() > prob {
					rv = false;
				}
			}
		}

		rv
	}

	fn consume(&mut self) {
		if !self.enabled {
			return;
		}
		if let Some(life) = self.max_life {
			self.consumed += 1;
			if self.consumed >= life {
				info!("Disabling rule {} due to max_life reached", &self.name);
				self.enabled = false;
			}
		}
	}

	fn notify_reply(&mut self, status: &StatusCode) {
		if !self.enabled {
			return;
		}
		let status_str = format!("{:?}", status);
		if let Some(check) = &self.disable_on {
			if check.is_match(&status_str) {
				info!("Disabling rule {} due to reply status {} matching disable_on rule", &self.name, &status_str);
				self.enabled = false;
				return;
			}
		}
		if let Some(check) = &self.keep_while {
			if ! check.is_match(&status_str) {
				info!("Disabling rule {} due to reply status {} not matching keep_while rule", &self.name, &status_str);
				self.enabled = false;
				return;
			}
		}
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
	log_level: Option<String>,
	log: Option<bool>,
	log_headers: Option<bool>,
	log_request_body: Option<bool>,
	max_request_log_size: Option<i64>,
	log_reply_body: Option<bool>,
	max_reply_log_size: Option<i64>,
	server_ssl_trust: Option<String>,
	server_ssl_key: Option<String>,
	filters: Option<toml::Table>,
	actions: Option<toml::Table>,
	rules: Option<toml::Table>,
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
			log_level: None,
			log: None,
			log_headers: None,
			log_request_body: None,
			log_reply_body: None,
			max_request_log_size: None,
			max_reply_log_size: None,
			server_ssl_trust: Self::env_str("SERVER_SSL_TRUST"),
			server_ssl_key: Self::env_str("SERVER_SSL_KEY"),
			filters: None,
			actions: None,
			rules: None,
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
		self.log_level = self.log_level.take().or(other.log_level);
		self.log = self.log.take().or(other.log);
		self.log_headers = self.log_headers.take().or(other.log_headers);
		self.log_request_body = self.log_request_body.take().or(other.log_request_body);
		self.max_request_log_size = self.max_request_log_size.take().or(other.max_request_log_size);
		self.log_reply_body = self.log_reply_body.take().or(other.log_reply_body);
		self.max_reply_log_size = self.max_reply_log_size.take().or(other.max_reply_log_size);
		self.server_ssl_trust = self.server_ssl_trust.take().or(other.server_ssl_trust);
		self.server_ssl_key = self.server_ssl_key.take().or(other.server_ssl_key);
		self.filters = self.filters.take().or(other.filters);
		self.actions = self.actions.take().or(other.actions);
		self.rules = self.rules.take().or(other.rules);
	}

	fn get_filters(&self) -> HashMap<String,ConfigFilter> {
		if self.filters.is_none() {
			return HashMap::new();
		}

		let mut rv = HashMap::new();
		let data = self.filters.as_ref().unwrap();
		for (k,v) in data.iter() {
			if let Some(cf) = ConfigFilter::parse(v) {
				rv.insert(k.to_string(),cf);
			}
		}
		return rv;
	}

	fn get_actions(&self) -> HashMap<String,ConfigAction> {
		if self.actions.is_none() {
			return HashMap::new();
		}

		let mut rv = HashMap::new();
		let data = self.actions.as_ref().unwrap();
		for (k,v) in data.iter() {
			if let Some(ca) = ConfigAction::parse(v) {
				rv.insert(k.to_string(),ca);
			}
		}
		return rv;
	}

	fn get_rules(&self) -> HashMap<String,ConfigRule> {
		if self.rules.is_none() {
			return HashMap::new();
		}

		let mut rv = HashMap::new();
		let data = self.rules.as_ref().unwrap();
		for (k,v) in data.iter() {
			if let Some(cr) = ConfigRule::parse(k.to_string(), v) {
				rv.insert(k.to_string(), cr);
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
	bind: SocketAddr,
	graceful_shutdown_timeout: Duration,
	server_ssl_trust: Option<PathBuf>,
	server_ssl_key: Option<PathBuf>,
	log_level: LevelFilter,
	default_action: ConfigAction,
	filters: HashMap<String,ConfigFilter>,
	actions: HashMap<String,ConfigAction>,
	rules: HashMap<String,ConfigRule>,
}

impl Config {
	pub fn load(content: &str) -> Result<Self, Box<dyn Error>> {
		let mut raw_cfg = RawConfig::from_env();
		let content_cfg: RawConfig = match toml::from_str(&content) {
			Ok(v) => v,
			Err(err) => return Err(Box::from(format!("Config parsing error: {}", err)))
		};
		raw_cfg.merge(content_cfg);

		let remote = raw_cfg.remote.as_ref().expect("Missing main remote host in configuration");

		Ok(Config {
			default_action: ConfigAction {
				remote: Some(RemoteConfig::build(remote)),
				rewrite_host: raw_cfg.rewrite_host,
				ssl_mode: Some(Self::parse_ssl_mode(&raw_cfg)),
				cafile: Self::parse_file(&raw_cfg.cafile),
				log: raw_cfg.log,
				log_headers: raw_cfg.log_headers,
				log_request_body: raw_cfg.log_request_body,
				max_request_log_size: raw_cfg.max_request_log_size,
				log_reply_body: raw_cfg.log_reply_body,
				max_reply_log_size: raw_cfg.max_reply_log_size,
			},
			bind: Self::parse_bind(&raw_cfg),
			graceful_shutdown_timeout: Self::parse_graceful_shutdown_timeout(&raw_cfg),
			server_ssl_trust: Self::parse_file(&raw_cfg.server_ssl_trust),
			server_ssl_key: Self::parse_file(&raw_cfg.server_ssl_key),
			log_level: Self::parse_log_level(&raw_cfg.log_level),
			filters: raw_cfg.get_filters(),
			actions: raw_cfg.get_actions(),
			rules: raw_cfg.get_rules(),
		})
	}

	fn get_actions<'a>(&'a mut self, method: &Method, path: &Uri, headers: &HeaderMap) -> (Vec<&'a ConfigAction>,Vec<String>) {
		let mut actions = Vec::new();
		let mut rulenames = Vec::new();

		for (rulename,rule) in self.rules.iter_mut() {
			if ! rule.matches(&self.filters, method, path, headers) {
				continue;
			}
			rule.consume();
			rulenames.push(rulename.clone());
			for aname in &rule.actions {
				if let Some(act) = self.actions.get(aname) {
					actions.push(act);
				}
			}
		}
		actions.push(&self.default_action);
		(actions, rulenames)
	}

	pub fn get_request_config(&mut self, method: &Method, path: &Uri, headers: &HeaderMap) -> (ConfigAction,Vec<String>) {
		let mut rv = ConfigAction::default();
		let (actions, rulenames) = self.get_actions(method, path, headers);
		for act in actions {
			rv.merge(act);
		}
		(rv, rulenames)
	}

	pub fn notify_reply(&mut self, rulenames: Vec<String>, status: &StatusCode) {
		for rule in rulenames {
			if let Some(r) = self.rules.get_mut(&rule) {
				r.notify_reply(status);
			}
		}
	}

	pub fn get_graceful_shutdown_timeout(&self) -> Duration {
		self.graceful_shutdown_timeout
	}

	pub fn get_bind(&self) -> SocketAddr {
		self.bind
	}

	pub fn server_version(&self) -> HttpVersionMode {
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

	pub fn get_log_level(&self) -> LevelFilter {
		self.log_level
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
	fn parse_log_level(value: &Option<String>) -> LevelFilter {
		let lev = value.as_ref()
			.and_then(|v| Some(v.to_lowercase()))
			.unwrap_or("".to_string());

		match lev.trim() {
			"trace" => LevelFilter::Trace,
			"debug" => LevelFilter::Debug,
			"info" => LevelFilter::Info,
			"warn" => LevelFilter::Warn,
			"error" => LevelFilter::Error,
			_ => LevelFilter::Info,
		}
	}

	fn parse_ssl_mode(rc: &RawConfig) -> SslMode {
		rc.ssl_mode
			.as_ref()
			.unwrap_or(&"builtin".to_string())
			.into()
	}
}

