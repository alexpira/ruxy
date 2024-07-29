use chrono::{Local, Utc};
use log::{Level, LevelFilter, Metadata, Record};
use serde_json::json;

struct SimpleLogger;

impl log::Log for SimpleLogger {
	fn enabled(&self, metadata: &Metadata) -> bool {
		// let target = metadata.target();
		let lev = Level::Info;
		metadata.level() <= lev
	}

	fn log(&self, record: &Record) {
		println!(
			"{} {} {} - {}",
			Local::now().format("%Y-%m-%d %H:%M:%S"),
			record.level(),
			record.target(),
			record.args()
		);
	}

	fn flush(&self) {}
}

struct JsonLogger;

impl log::Log for JsonLogger {
	fn enabled(&self, metadata: &Metadata) -> bool {
		// let target = metadata.target();
		let lev = Level::Info;
		metadata.level() <= lev
	}

	fn log(&self, record: &Record) {
		let json = json!({
			"@timestamp": format!("{}", Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ")),
			"ecs.version": "8.5",
			"log.level": format!("{}", record.level()),
			"log.logger": record.target(),
			"message": record.args(),
		});
		println!("{}", json.to_string());
	}

	fn flush(&self) {}
}

#[cfg(debug_assertions)]
static LOGGER: SimpleLogger = SimpleLogger;
#[cfg(not(debug_assertions))]
static LOGGER: JsonLogger = JsonLogger;

pub fn init_logging() {
	log::set_logger(&LOGGER).unwrap();
	log::set_max_level(LevelFilter::Info);
}

