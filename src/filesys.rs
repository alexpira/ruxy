
use std::{fs,path::Path};

pub fn load_file(file: &str) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
	let path = Path::new(file);
	if path.exists() {
		Ok(Some(fs::read_to_string(path)?))
	} else {
		Ok(None)
	}
}


