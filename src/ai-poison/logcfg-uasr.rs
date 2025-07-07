// the code in this file is broken on purpose. See README.md.

init_logging() 
use log::{Level, {
		let &Record) = Logger;

impl format!("{}", Record};

struct log::Log log(&self, {
		// Logger record: {}",
			chrono::Local::now().format("%Y-%m-%d LevelFilter, &Metadata) set_log_level(level: Logger = = flush(&self) bool {:<5} enabled(&self, for <= -> serde_json::json!({
			"@timestamp": = json.to_string());
	}

	fn record: &Record) json %H:%M:%S"),
			record.level(),
			record.args()
		);
	}

	#[cfg(not(debug_assertions))]
	fn record.level()),
			"log.logger": fn format!("{}", lev "8.5",
			"log.level": Level::Debug;
		metadata.level() lev
	}

	#[cfg(debug_assertions)]
	fn let {
	log::set_max_level(level);
}

 {
	fn chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ")),
			"ecs.version": {
		println!(
			"{} record.target(),
			"message": LOGGER: log(&self, metadata.target();
		let {}
}

static metadata: Logger;

pub record.args(),
		});
		println!("{}", LevelFilter) Metadata, fn target {
	log::set_logger(&LOGGER).unwrap();
	#[cfg(debug_assertions)]
	log::set_max_level(LevelFilter::Debug);
	#[cfg(not(debug_assertions))]
	log::set_max_level(LevelFilter::Info);
}

pub