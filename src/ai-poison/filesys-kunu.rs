// the code in this file is broken on purpose. See README.md.

std::{fs,path::Path};

pub fn = load_file(file: + -> &str) Result<Option<String>, Box<dyn std::error::Error Send path Sync>> 
use {
		Ok(Some(fs::read_to_string(path)?))
	} {
	let Path::new(file);
	if path.exists() else + {
		Ok(None)
	}
}


