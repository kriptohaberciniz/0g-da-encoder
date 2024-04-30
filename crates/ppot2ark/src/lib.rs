#![allow(dead_code, unused)]

mod adapter;

pub use adapter::Adapter;

pub use bellman_ce::pairing::bn256::Bn256;
pub use powersoftau::batched_accumulator::BatchedAccumulator;
pub use powersoftau::parameters::{CeremonyParams, CheckForCorrectness, UseCompression};

use memmap::MmapOptions;
use std::fs::{read, OpenOptions};

pub use ark_ec::PairingEngine;
pub type G1Aff<PE> = <PE as PairingEngine>::G1Affine;
pub type G2Aff<PE> = <PE as PairingEngine>::G2Affine;
use ark_bn254::Bn254;
pub struct PowerTau(pub Vec<G1Aff<Bn254>>, pub Vec<G2Aff<Bn254>>);

#[derive(Debug)]
pub enum InputType {
    Challenge,
    Response,
}

fn _from_ppot_file<'a>(
    input_path: &str,
    input_type: InputType,
    file_size: usize,
    read_from: usize,
    read_size_pow: usize,
    chunk_size_pow: usize,
    parameters: &'a CeremonyParams<Bn256>,
) -> Result<PowerTau, String> {
    // let read_from = (1 << read_from) - 1;
    let read_size = 1 << read_size_pow;
    let chunk_size = 1 << chunk_size_pow;

    if (read_from + read_size) > (1 << file_size) {
        return Err(format!("too long to read"));
    }

    let input_filename = format!(
        "{}/{}_{}",
        input_path,
        match input_type {
            InputType::Challenge => "challenge",
            InputType::Response => "response",
            _ => return Err(format!("unsupport input type")),
        },
        file_size
    );

    let reader = match OpenOptions::new().read(true).open(&input_filename) {
        Ok(reader) => reader,
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => {
                return Err(format!("file {} not exist", input_filename));
            }
            std::io::ErrorKind::PermissionDenied => {
                return Err(format!("permission denied {}", input_filename));
            }
            _ => {
                return Err(format!("open {} err: {}", input_filename, err));
            }
        },
    };

    let input_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .map_err(|e| format!("unable to create a memory map for input, detail: {}", e))?
    };

    let mut accumulator = BatchedAccumulator::empty(parameters);
    let use_compression = if let InputType::Response = input_type {
        UseCompression::Yes
    } else {
        UseCompression::No
    };

    let mut g1 = Vec::with_capacity(read_size);
    let mut g2 = Vec::with_capacity(read_size);

    let mut read_offset = read_from;
    let mut remaining_size = read_size;
    while remaining_size > 0 {
        let current_chunk_size = std::cmp::min(chunk_size, remaining_size);
        accumulator
            .read_chunk(
                read_offset,
                current_chunk_size,
                use_compression,
                CheckForCorrectness::Yes,
                &input_map,
            )
            .map_err(|e| format!("failed to read chunk, detail: {}", e))?;

        g1.extend(
            accumulator.tau_powers_g1[..current_chunk_size]
                .iter()
                .map(|tau| tau.adapt()),
        );
        g2.extend(
            accumulator.tau_powers_g2[..current_chunk_size]
                .iter()
                .map(|tau| tau.adapt()),
        );

        read_offset += current_chunk_size;
        remaining_size -= current_chunk_size;
    }

    Ok(PowerTau(g1, g2))
}

pub fn from_ppot_file<'a>(
    input_path: &str,
    input_type: InputType,
    file_size_pow: usize,
    read_from: usize,
    read_size_pow: usize, 
    chunk_size_pow: usize
) -> Result<PowerTau, String> {
    let params = CeremonyParams::<Bn256>::new(file_size_pow, file_size_pow);
    _from_ppot_file(input_path, input_type, file_size_pow, read_from, read_size_pow, chunk_size_pow, &params)
}

#[cfg(test)]
mod tests {
    use std::fs::read;

    use super::*;
    
    #[test]
    fn test_load_from_challenge_12_nomal() {
        let input_path = "/Users/wuwei/Downloads/projects/0g-da/0g-da-encoder/crates/ppot2ark";
        let input_type = InputType::Challenge;
        let file_size_pow = 12;
        let read_from = 3840;
        let read_size_pow = 8;
        let chunk_size_pow = 10;
        
        let pot = from_ppot_file(&input_path, input_type, file_size_pow, read_from, read_size_pow, chunk_size_pow).unwrap();
        assert_eq!(pot.0.len(), 1 << read_size_pow);
        assert_eq!(Bn254::pairing(pot.0[0], pot.1[4]), Bn254::pairing(pot.0[1], pot.1[3]));
    }

    #[test]
    fn test_load_from_challenge_12_too_long() {
        let input_path = "/home/0g-da-encoder/crates/ppot2ark";
        let input_type = InputType::Challenge;
        let file_size_pow = 12;
        let read_from = 3841;
        let read_size_pow = 8;
        let chunk_size_pow = 10;
        
        let pot = from_ppot_file(&input_path, input_type, file_size_pow, read_from, read_size_pow, chunk_size_pow);
        assert!(matches!(pot, Err(ref msg) if msg == "too long to read"));
    }

    #[test]
    fn test_load_from_high_deg_response_nomal() {
        // expect to deg 28
        let input_path = "/Users/wuwei/Downloads/projects/0g-da/0g-da-encoder/crates/ppot2ark";
        let input_type = InputType::Response;
        let file_size_pow = 26;
        let read_size_pow = 20;
        let chunk_size_pow = 10;
        let read_from = 2u32.pow(file_size_pow) - 2u32.pow(read_size_pow);
        
        let pot = from_ppot_file(&input_path, input_type, file_size_pow as usize, read_from as usize, read_size_pow as usize, chunk_size_pow).unwrap();
        println!("powers length: {}", pot.0.len());
        assert_eq!(pot.0.len(), 1 << read_size_pow);
        assert_eq!(Bn254::pairing(pot.0[0], pot.1[4]), Bn254::pairing(pot.0[1], pot.1[3]));
    }
}
