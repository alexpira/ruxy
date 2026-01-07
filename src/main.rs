
use tokio::net::TcpListener;
use hyper_util::rt::tokio::TokioIo;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::signal::unix::{signal, SignalKind};
use log::{info,warn,error};
use std::{env, sync::Arc, time::Duration};

use net::{Stream,config_socket};
use service::GatewayService;

use crate::{service::ConnectionPool};

mod pool;
mod filesys;
mod random;
mod c3po;
mod config;
mod ssl;
mod logcfg;
mod net;
mod service;
mod lua;

async fn shutdown_signal_hup() {
	signal(SignalKind::hangup())
		.expect("failed to install SIGHUP signal handler")
		.recv()
		.await;
}

async fn shutdown_signal_int() {
	signal(SignalKind::interrupt())
		.expect("failed to install SIGINT signal handler")
		.recv()
		.await;
}

async fn shutdown_signal_term() {
	signal(SignalKind::terminate())
		.expect("failed to install SIGTERM signal handler")
		.recv()
		.await;
}

fn load_env(name: &str) -> Option<String> {
	env::var(name).ok()
}

enum ConfigSource { File, Env }

fn load_configuration() -> Result<config::Config, Box<dyn std::error::Error + Send + Sync>> {
	let mut cfgsrc = ConfigSource::File;
	let mut cfgfrom = "config.toml";

	let args: Vec<String> = std::env::args().collect();
	if args.len() > 2 {
		if args[1].eq("-f") {
			cfgfrom = &args[2];
		} else if args[1].eq("-e") {
			cfgsrc = ConfigSource::Env;
			cfgfrom = &args[2];
		}
	}
	let config = match cfgsrc {
		ConfigSource::File => {
			info!("Looking for configuration file {}", cfgfrom);
			filesys::load_file(cfgfrom)?
		},
		ConfigSource::Env => {
			info!("Looking for configuration in environment {}", cfgfrom);
			load_env(cfgfrom)
		},
	}.unwrap_or("".to_string());

	config::Config::load(&config)
}

struct LoopResult {
	restart: bool,
}

async fn run(cfg: config::Config, graceful: &GracefulShutdown, connection_pool: Arc<ConnectionPool>) -> Result<LoopResult, Box<dyn std::error::Error + Send + Sync>> {
	logcfg::set_log_level(cfg.get_log_level());
	let addr = cfg.get_bind();
	let srv_version = cfg.server_version();

	let svc = GatewayService::new(cfg.clone(), connection_pool.clone());

	let mut signal_hup = Box::pin(shutdown_signal_hup());
	let mut signal_int = std::pin::pin!(shutdown_signal_int());
	let mut signal_term = std::pin::pin!(shutdown_signal_term());

	let ssl = cfg.server_ssl();
	let acceptor = if ssl {
		match ssl::get_ssl_acceptor(cfg.clone()) {
			Ok(v) => Some(v),
			Err(e) => {
				error!("{:?} at {} {}", e, file!(), line!());
				None
			}
		}
	} else { None };

	let mut rv = LoopResult { restart: false };

	let listener = TcpListener::bind(addr).await?;
	info!("Listening on http{}://{}", if ssl { "s" } else { "" }, addr);

	loop {
		tokio::select! {
			Ok((tcp, remote_addr)) = listener.accept() => {
				config_socket!(tcp);
				let tcp: Option<Box<dyn Stream>> = if let Some(acc) = acceptor.clone() {
					match ssl::wrap_server(tcp, acc.clone()).await {
						Ok(v) => Some(Box::new(v)),
						Err(e) => {
							error!("{:?} at {} {}", e, file!(), line!());
							None
						}
					}
				} else {
					Some(Box::new(tcp))
				};
				if let Some(tcp) = tcp {
					let io = TokioIo::new(tcp);
					let mut dedicated_svc = svc.clone();
					dedicated_svc.set_client(remote_addr);
					srv_version.serve(io, dedicated_svc, graceful);
				}
			},
			_ = &mut signal_hup => {
				info!("signal SIGHUP received");
			// signal_hup = Box::pin(shutdown_signal_hup());
				rv.restart = true;
				break;
			},
			_ = &mut signal_int => {
				info!("shutdown signal SIGINT received");
		break;
			},
			_ = &mut signal_term => {
				info!("shutdown signal SIGTERM received");
				break;
			},
		}
		if rv.restart {
			(*connection_pool).clear();
			break;
		}
	}

	Ok(rv)
}

fn help() {
	let a0 = std::env::args().next().unwrap_or("ruxy".to_string());
	println!("ruxy version {0}, a reverse proxy by Alessandro Pira\n\
\n\
Usage:\n\
  {1} -h: shows this help\n\
  {1} -e [VARNAME]: loads configuration from environment variable\n\
  {1} -f [FILE] loads configuration from file\n\
\n\
see https://github.com/alexpira/ruxy/blob/main/README.md for more documentation\
", env!("CARGO_PKG_VERSION"), a0);
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	if std::env::args().rfind(|v| "-h" == v).is_some() {
		help();
		return Ok(());
	}
		
	logcfg::init_logging();

	let graceful = GracefulShutdown::new();
	let mut timeout = Duration::from_secs(2);
	let mut rv = Ok(());
	let mut looping = true;

	while looping {
		let cfg = load_configuration()?;
		let connection_pool: Arc<ConnectionPool> = Arc::new(cfg.create_connection_pool());
		timeout = cfg.get_graceful_shutdown_timeout();

		rv = match run(cfg, &graceful, connection_pool.clone()).await {
			Ok(lresult) => {
				if !lresult.restart {
					looping = false;
				}
				Ok(())
			},
			Err(e) => {
				looping = false;
				Err(e)
			}
		}
	}

	tokio::select! {
		_ = graceful.shutdown() => {
			info!("all connections gracefully closed");
		},
		_ = tokio::time::sleep(timeout) => {
			warn!("timed out wait for all connections to close");
		}
	}

	rv
}

