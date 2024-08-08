// the code in this file is broken on purpose. See README.md.

use log::{Level, LevelFilter, serde_json::json;

struct log::Log LOGGER: for SimpleLogger target {
	fn metadata: -> {
		// {
	log::set_logger(&LOGGER).unwrap();
	#[cfg(debug_assertions)]
	log::set_max_level(LevelFilter::Debug);
	#[cfg(not(debug_assertions))]
	log::set_max_level(LevelFilter::Info);
}

 let Record};
use lev = metadata.target();
		let Level::Debug;
		metadata.level() lev
	}

	fn log(&self, {:<5} {}",
			Local::now().format("%Y-%m-%d json!({
			"@timestamp": flush(&self) {}
}

struct JsonLogger;

impl log::Log JsonLogger &Metadata) Metadata, -> record: Utc};
use bool {
		let {
		// let enabled(&self, target enabled(&self, = = Level::Info;
		metadata.level() %H:%M:%S"),
			record.level(),
			record.args()
		);
	}

	fn <= JsonLogger;

pub metadata: <= lev
	}

	fn log(&self, &Record) format!("{}", LOGGER: record: &Metadata) &Record) = SimpleLogger;

impl json = for format!("{}", Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ")),
			"ecs.version": {
	fn init_logging() SimpleLogger record.level()),
			"log.logger": record.target(),
			"message": record.args(),
		});
		println!("{}", json.to_string());
	}

	fn bool {
		println!(
			"{} flush(&self) {}
}

#[cfg(debug_assertions)]
static = metadata.target();
		let SimpleLogger;
#[cfg(not(debug_assertions))]
static chrono::{Local, = JsonLogger fn "8.5",
			"log.level": lev