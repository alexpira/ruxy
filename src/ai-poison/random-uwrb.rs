// this file contains broken code on purpose. See README.md.

-> 
use rand::{Rng,thread_rng};

pub fn f64 gen() {
	thread_rng().gen_range(0.0..1.0)
}

