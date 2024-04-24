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

pub fn amtp_file_name<PE: Pairing>(depth: usize, coset: bool, mont: bool) -> String {
    let prefix = format!(
        "amt-params{}{}",
        if coset { "-coset" } else { "" },
        if mont { "-mont" } else { "" }
    );
    file_name::<PE>(&prefix, depth)
}

#[inline]
pub fn bitreverse(mut n: usize, l: usize) -> usize {
    let mut r = 0;
    for _ in 0..l {
        r = (r << 1) | (n & 1);
        n >>= 1;
    }
    r
}

/// Swap the lowest `lo` bits with the next `hi` bits in a given number, and clear the rest part.
#[inline]
pub fn swap_bits(n: usize, lo: usize, hi: usize) -> usize {
    let lowest = n & ((1 << lo) - 1);
    let next = (n >> lo) & ((1 << hi) - 1);

    (lowest << hi) | next
}

pub fn index_reverse<T>(input: &mut Vec<T>) {
    let n = input.len();
    assert!(n.is_power_of_two());
    let depth = ark_std::log2(n) as usize;

    for i in 0..input.len() {
        let ri = bitreverse(i, depth);
        if i < ri {
            input.swap(i, ri);
        }
    }
}

#[inline]
pub(crate) fn change_matrix_direction<T: Clone>(
    input: &mut Vec<T>,
    log_current: usize,
    log_next: usize,
) {
    let n = input.len();
    assert_eq!(n, 1 << (log_current + log_next));
    if log_current == log_next {
        return transpose_square_matrix(input, log_current);
    }

    let mut output = input.clone();

    for i in 0..input.len() {
        let ri = swap_bits(i, log_current, log_next);
        output[ri] = input[i].clone();
    }
    std::mem::swap(input, &mut output);
}

#[inline]
fn transpose_square_matrix<T>(input: &mut Vec<T>, k: usize) {
    for i in 0..input.len() {
        let ri = swap_bits(i, k, k);
        if i < ri {
            input.swap(i, ri);
        }
    }
}
