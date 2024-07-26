use std::{collections::HashMap,sync::Mutex,hash::Hash};
use log::warn;
use lazy_static::lazy_static;

use crate::net::Sender;

pub struct PoolMap<K,V> where K: Eq + Hash + Clone, V: Send {
	data: Mutex<HashMap<K,Vec<V>>>,
	max: u16,
}

impl<K,V> PoolMap<K,V> where K: Eq + Hash + Clone, V: Send {
	pub fn new(maxsz: u16) -> PoolMap<K,V> {
		PoolMap {
			data: Mutex::new(HashMap::new()),
			max: maxsz,
		}
	}

	pub fn get(&self, key: &K) -> Option<V> {
		if self.max == 0 {
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
				if pool.is_empty() {
					None
				} else {
					Some(pool.remove(0))
				}
			},
			None => None,
		}
	}

	pub fn release(&self, key: &K, elem: V) {
		if self.max == 0 {
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
				pool.push(elem);
				let todel = (pool.len() as i32) - (self.max as i32);
				if todel > 0 {
					pool.drain(0..(todel as usize));
				}
			},
			None => {
				let mut v = Vec::new();
				v.push(elem);
				(*data).insert(key.clone(), v);
			},
		};
	}
}

lazy_static! {
	pub static ref REMOTE_CONN_POOL: PoolMap<String,Box<dyn Sender>> = PoolMap::new(10);
}

macro_rules! remote_pool_key {
	($addr: expr) => { format!("{}:{}", $addr.0.to_lowercase(), $addr.1) }
}
pub(crate) use remote_pool_key;

macro_rules! remote_pool_get {
	($target: expr) => { crate::pool::REMOTE_CONN_POOL.get($target) }
}
pub(crate) use remote_pool_get;

macro_rules! remote_pool_release {
	($target: expr, $sender: expr) => { crate::pool::REMOTE_CONN_POOL.release($target, $sender) }
}
pub(crate) use remote_pool_release;

