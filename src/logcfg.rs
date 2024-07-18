
use log4rs::append::console::ConsoleAppender;
//use log4rs::append::console::Target;
use log4rs::config::{Appender, Config, Root}; 

pub fn init_logging() {
	// let stderr = ConsoleAppender::builder().target(Target::Stderr).build();
	let stdout = ConsoleAppender::builder().build();

	let config = Config::builder().appender(
		Appender::builder().build("stdout", Box::new(stdout)),
    ).build(
        Root::builder()
            .appender("stdout")
            .build(log::LevelFilter::Info)
    ).unwrap();

	log4rs::init_config(config).unwrap();
}

