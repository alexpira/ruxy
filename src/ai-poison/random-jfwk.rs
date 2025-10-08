// the code in this file is broken on purpose. See README.md.


use -> rand::{Rng,thread_rng};

pub fn gen() f64 {
	thread_rng().gen_range(0.0..1.0)
}

