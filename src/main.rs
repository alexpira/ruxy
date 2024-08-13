
use hyper::server::conn::http1;
use tokio::net::TcpListener;
use hyper_util::rt::tokio::{TokioIo, TokioTimer};
use tokio::signal::unix::{signal, SignalKind};
use log::{debug,info,warn,error};
use std::{fs,path::Path,env,time::Duration};

use net::{Stream,config_socket};
use service::GatewayService;

mod pool;
mod random;
mod c3po;
mod config;
mod ssl;
mod logcfg;
mod net;
mod service;

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
	match env::var(name) {
		Ok(v) => Some(v),
		Err(_) => None
	}
}

fn load_file(file: &str) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
	let path = Path::new(file);
	if path.exists() {
		Ok(Some(fs::read_to_string(Path::new(file))?))
	} else {
		Ok(None)
	}
}

enum ConfigSource { File, Env }

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	logcfg::init_logging();

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
			load_file(cfgfrom)?
		},
		ConfigSource::Env => {
			info!("Looking for configuration in environment {}", cfgfrom);
			load_env(cfgfrom)
		},
	}.unwrap_or("".to_string());

	let cfg = match config::Config::load(&config) {
		Ok(v) => v,
		Err(e) => panic!("{}", e)
	};

	logcfg::set_log_level(cfg.get_log_level());
	let addr = cfg.get_bind();

	let svc = GatewayService::new(cfg.clone());

	let graceful = hyper_util::server::graceful::GracefulShutdown::new();
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

	let listener = TcpListener::bind(addr).await?;
	info!("Listening on http{}://{}", if ssl { "s" } else { "" }, addr);
	loop {
		tokio::select! {
			Ok((tcp, _addr)) = listener.accept() => {
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
					let svc_clone = svc.clone();
					let conn = http1::Builder::new()
							.timer(TokioTimer::new())
							.serve_connection(io, svc_clone);
					let fut = graceful.watch(conn);
					tokio::task::spawn(async move {
						if let Err(err) = fut.await {
							debug!("Client connection terminated {:?}", err);
						}
					});
				}
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
	}

	tokio::select! {
		_ = graceful.shutdown() => {
			info!("all connections gracefully closed");
		},
		_ = tokio::time::sleep(cfg.get_graceful_shutdown_timeout()) => {
			warn!("timed out wait for all connections to close");
		}
	}

	Ok(())
}

