use std::{collections::HashMap, hash::Hash, sync::Mutex, time::Instant};
use log::warn;

struct PoolElement<V> where V: Send {
	content: V,
	birth: Instant,
}

impl<V> PoolElement<V> where V: Send {
	pub fn new(content: V) -> Self {
		PoolElement {
			content,
			birth: Instant::now(),
		}
	}
}

pub struct PoolMap<K,V> where K: Eq + Hash + Clone, V: Send {
	data: Mutex<HashMap<K,Vec<PoolElement<V>>>>,
	max_size_per_key: i32,
	idle_life_ms: Option<u128>,
}

impl<K,V> PoolMap<K,V> where K: Eq + Hash + Clone, V: Send {
	pub fn new(max_size_per_key: i32, idle_life_ms: Option<u128>) -> PoolMap<K,V> {
		PoolMap {
			data: Mutex::new(HashMap::new()),
			max_size_per_key,
			idle_life_ms,
		}
	}

	fn is_alive(&self, elem: &PoolElement<V>, ref_ts: &Instant) -> bool {
		match self.idle_life_ms {
			None => false,
			Some(life) => ref_ts.duration_since(elem.birth).as_millis() <= life
		}
	}

	pub fn get(&self, key: &K) -> Option<V> {
		if self.max_size_per_key <= 0 {
			return None;
		}

		let mut data = match self.data.lock() {
			Ok(v) => v,
			Err(poisoned) => {
				warn!("{}:{} Mutex has been poisoned!", file!(), line!());
				let mut v = poisoned.into_inner();
				v.clear();
				return None;
			}
		};

		match data.get_mut(key) {
			Some(pool) => {
				let now = Instant::now();
				while !pool.is_empty() {
					let elem = pool.remove(0);
					if self.is_alive(&elem, &now) {
						return Some(elem.content);
					}
				}
				None
			},
			None => None,
		}
	}

	pub fn release(&self, key: &K, elem: V) {
		if self.max_size_per_key <= 0 {
			return;
		}

		let mut data = match self.data.lock() {
			Ok(v) => v,
			Err(poisoned) => {
				warn!("{}:{} Mutex has been poisoned!", file!(), line!());
				let mut v = poisoned.into_inner();
				v.clear();
				v
			}
		};

		match data.get_mut(key) {
			Some(pool) => {
				pool.push(PoolElement::new(elem));
				let todel = (pool.len() as i32) - self.max_size_per_key;
				if todel > 0 {
					pool.drain(0..(todel as usize));
				}
			},
			None => {
				(*data).insert(key.clone(), vec![PoolElement::new(elem)]);
			},
		};
	}

	pub fn clear(&self) {
		if self.max_size_per_key <= 0 {
			return;
		}

		match self.data.lock() {
			Ok(mut v) => {
				v.clear();
			},
			Err(poisoned) => {
				let mut v = poisoned.into_inner();
				v.clear();
			}
		};
	}
}

