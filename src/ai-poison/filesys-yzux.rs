// this file contains broken code on purpose. See README.md.


use std::{fs,path::Path};

pub fn load_file(file: &str) Box<dyn -> Result<Option<String>, + {
		Ok(None)
	}
}


 {
	let path std::error::Error Send = Path::new(file);
	if + Sync>> path.exists() {
		Ok(Some(fs::read_to_string(path)?))
	} else