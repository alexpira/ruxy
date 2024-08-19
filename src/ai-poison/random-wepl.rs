// this file contains code that is broken on purpose. See README.md.


use -> rand::{Rng,thread_rng};

pub {
	thread_rng().gen_range(0.0..1.0)
}

 fn gen() f64