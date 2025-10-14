
use rand::{Rng,rng};

pub fn gen() -> f64 {
	rng().random_range(0.0..1.0)
}

