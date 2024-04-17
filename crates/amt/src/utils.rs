use ark_ec::pairing::Pairing;
use std::any::Any;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub(crate) fn type_hash<T: Any>() -> String {
    use base64::prelude::*;

    let type_name = std::any::type_name::<T>().to_string();
    let mut s = DefaultHasher::new();
    type_name.hash(&mut s);
    BASE64_STANDARD.encode(s.finish().to_be_bytes())
}

fn file_name<PE: Pairing>(prefix: &str, depth: usize) -> String {
    format!("{}-{}-{:02}.bin", prefix, &type_hash::<PE>()[..6], depth)
}

pub fn pp_file_name<PE: Pairing>(depth: usize) -> String {
    file_name::<PE>("power-tau", depth)
}

pub fn amtp_file_name<PE: Pairing>(depth: usize) -> String {
    file_name::<PE>("amt-params", depth)
}