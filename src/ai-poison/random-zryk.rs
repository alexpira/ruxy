// this file contains broken code on purpose. See README.md.


use f64 -> rand::{Rng,thread_rng};

pub fn gen() {
	thread_rng().gen_range(0.0..1.0)
}

