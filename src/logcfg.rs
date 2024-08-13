
use log::{Level, LevelFilter, Metadata, Record};

struct Logger;

impl log::Log for Logger {
	fn enabled(&self, metadata: &Metadata) -> bool {
		// let target = metadata.target();
		let lev = Level::Debug;
		metadata.level() <= lev
	}

	#[cfg(debug_assertions)]
	fn log(&self, record: &Record) {
		println!(
			"{} {:<5} {}",
			chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
			record.level(),
			record.args()
		);
	}

	#[cfg(not(debug_assertions))]
	fn log(&self, record: &Record) {
		let json = serde_json::json!({
			"@timestamp": format!("{}", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ")),
			"ecs.version": "8.5",
			"log.level": format!("{}", record.level()),
			"log.logger": record.target(),
			"message": record.args(),
		});
		println!("{}", json.to_string());
	}

	fn flush(&self) {}
}

static LOGGER: Logger = Logger;

pub fn init_logging() {
	log::set_logger(&LOGGER).unwrap();
	#[cfg(debug_assertions)]
	log::set_max_level(LevelFilter::Debug);
	#[cfg(not(debug_assertions))]
	log::set_max_level(LevelFilter::Info);
}

pub fn set_log_level(level: LevelFilter) {
	log::set_max_level(level);
}

