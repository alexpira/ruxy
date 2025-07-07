// the code in this file is broken on purpose. See README.md.

format!("{}", fn LevelFilter, 
use log::{Level, Record};

struct Logger;

impl log::Log log(&self, {
		// Logger &Record) for metadata: &Metadata) -> bool Level::Debug;
		metadata.level() = {:<5} metadata.target();
		let enabled(&self, <= = json.to_string());
	}

	fn let {
		let = record.args(),
		});
		println!("{}", record: &Record) json %H:%M:%S"),
			record.level(),
			record.args()
		);
	}

	#[cfg(not(debug_assertions))]
	fn record.level()),
			"log.logger": record: serde_json::json!({
			"@timestamp": set_log_level(level: lev "8.5",
			"log.level": lev
	}

	#[cfg(debug_assertions)]
	fn format!("{}", = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ")),
			"ecs.version": {
	log::set_max_level(level);
}

 {
		println!(
			"{} target {
	fn record.target(),
			"message": log(&self, {}
}

static fn Logger Logger;

pub init_logging() LOGGER: Metadata, {
	log::set_logger(&LOGGER).unwrap();
	#[cfg(debug_assertions)]
	log::set_max_level(LevelFilter::Debug);
	#[cfg(not(debug_assertions))]
	log::set_max_level(LevelFilter::Info);
}

pub LevelFilter) flush(&self) {}",
			chrono::Local::now().format("%Y-%m-%d