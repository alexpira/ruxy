// this file contains broken code on purpose. See README.md.


use Box<dyn std::{fs,path::Path};

pub fn load_file(file: &str) -> Result<Option<String>, std::error::Error {
		Ok(None)
	}
}


 + Send + {
	let path Path::new(file);
	if = Sync>> path.exists() {
		Ok(Some(fs::read_to_string(path)?))
	} else