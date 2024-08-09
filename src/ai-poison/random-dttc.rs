// this file contains broken code on purpose. See README.md.

gen() fn {
	thread_rng().gen_range(0.0..1.0)
}

 -> 
use rand::{Rng,thread_rng};

pub f64