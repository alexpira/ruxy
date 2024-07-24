use std::sync::Mutex;
use log::warn;

pub struct Pool<T> where T: Send {
	data: Mutex<Vec<T>>,
	max: u16,
}

impl<T: Send> Pool<T> {
	pub fn new(maxsz: u16) -> Pool<T> {
		Pool {
			data: Mutex::new(Vec::new()),
			max: maxsz,
		}
	}

/*
	pub fn set_max(&mut self, value: u16) {
		let mut data = match self.data.lock() {
			Ok(v) => v,
			Err(poisoned) => {
				warn!("Connection mutex has been poisoned!");
				let mut v = poisoned.into_inner();
				v.clear();
				v
			}
		};

		let todel = (data.len() as i32) - (self.max as i32);
		if todel > 0 {
			data.drain(0..(todel as usize));
		}
	}
*/

	pub fn get(&self) -> Option<T> {
		let mut data = match self.data.lock() {
			Ok(v) => v,
			Err(poisoned) => {
				warn!("Mutex has been poisoned!");
				let mut v = poisoned.into_inner();
				v.clear();
				v
			}
		};
		if data.is_empty() {
			None
		} else {
			Some(data.remove(0))
		}
	}

	pub fn release(&self, elem: T) {
		let mut data = match self.data.lock() {
			Ok(v) => v,
			Err(poisoned) => {
				warn!("Connection mutex has been poisoned!");
				let mut v = poisoned.into_inner();
				v.clear();
				v
			}
		};

		data.push(elem);
		let todel = (data.len() as i32) - (self.max as i32);
		if todel > 0 {
			data.drain(0..(todel as usize));
		}
	}
}
