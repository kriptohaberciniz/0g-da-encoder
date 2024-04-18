use std::sync::mpsc::SendError;

use crate::types::*;
use ark_ec::{bn::Bn, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_std::{iterable::Iterable, Zero};
use ethereum_types::H256;
use ark_bn254::{Fr as Scalar, G1Affine, G1Projective};
use ark_ff::{fields::Field, MontConfig, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalSerialize, SerializationError};
//use once_cell::sync::Lazy;
// use transpose::transpose;

fn raw_unit_to_scalar(chunk: &[u8]) -> Scalar {
    // <Scalar as PrimeField>::from_le_bytes_mod_order(&chunk) // 76ms
    // safety: chunk.len() == 31 for ark_bn254
    <Scalar as Field>::from_random_bytes(&chunk).unwrap() // 33 ms
}

pub fn raw_data_to_raw_blob(data: &RawData) -> RawBlob {
    let raw_blob_1d: Vec<_> = data.chunks(RAW_UNIT).map(raw_unit_to_scalar).collect();
    RawBlob(raw_blob_1d)
}

// rs_encode for each row of matrix (in place)
pub fn rs_encode_blobn_cols(matrix: &mut Vec<Vec<Scalar>>) -> () {
    // all rows use the same domain_blob_row_n and the same domain_blob_row_n2
    let domain_blob_row_n = Radix2EvaluationDomain::<Scalar>::new(BLOB_ROW_N).unwrap();
    let domain_blob_row_n2 = Radix2EvaluationDomain::<Scalar>::new(BLOB_ROW_N2).unwrap();
    // RS encode for each row of matrix
    matrix.iter_mut().for_each(|column_data| {
        domain_blob_row_n.ifft_in_place(column_data);
        domain_blob_row_n2.fft_in_place(column_data);
    });
}

/// RS encode for each col of raw_blob
pub fn raw_blob_to_encoded(raw_blob: &RawBlob) -> EncodedBlobEncoded {
    // transpose raw_blob
    let mut raw_blob_transpose: Vec<Vec<Scalar>> = (0..BLOB_COL_N)
        .map(|col_index| (0..BLOB_ROW_N).map(|row_index| raw_blob[(row_index << BLOB_COL_LOG) + col_index].clone()).collect::<Vec<Scalar>>())
        .collect();
    // RS encode for each row of raw_blob_transpose, i.e., for each col of raw_blob
    rs_encode_blobn_cols(&mut raw_blob_transpose);
    // transpose back and flat
    let encoded_flatten: Vec<Scalar> = (0..BLOB_ROW_N << 1)
        .flat_map(|row_index| raw_blob_transpose.iter().map(|col| col[row_index].clone()).collect::<Vec<Scalar>>())
        .collect();
    EncodedBlobEncoded(encoded_flatten)
}

pub fn coeffs_to_commitment(coeffs: &Vec<Scalar>, setup_g1: &SimulateSetupG1) -> G1Affine {
    let coeffs_repr: Vec<_> = coeffs.iter().map(|x| MontConfig::into_bigint(*x)).collect();
    G1Projective::msm_bigint(&setup_g1[..coeffs_repr.len()], &coeffs_repr).into_affine()
}

pub fn evals_to_commitment(_evals: &[Scalar], domain: Radix2EvaluationDomain::<Scalar>, setup_g1: &SimulateSetupG1) -> G1Affine {
    let mut evals = _evals.to_vec();
    domain.ifft_in_place(&mut evals);
    coeffs_to_commitment(&evals, setup_g1)
}

/// KZG commit for each row of raw_blob
pub fn encoded_to_row_commitments(encoded: &EncodedBlobEncoded, setup_g1: &SimulateSetupG1) -> RowCommitments {
    // all rows use the same domain_blob_col_n
    let domain_blob_col_n = Radix2EvaluationDomain::<Scalar>::new(BLOB_COL_N).unwrap();
    // KZG commitment
    let row_commitments: Vec<_> = encoded
        .chunks(BLOB_COL_N)
        .map(|row| evals_to_commitment(row, domain_blob_col_n, setup_g1))
        .collect();
    RowCommitments(row_commitments)
}

pub fn g1_to_scalar(g1: &G1Affine) -> Result<Scalar, SerializationError> {
    let mut compressed_bytes = Vec::new();
    g1.serialize_compressed(&mut compressed_bytes)?;
    Ok(<Scalar as PrimeField>::from_le_bytes_mod_order(&compressed_bytes))
}

pub fn coeffs_to_multi_proof(coeffs: &Vec<Scalar>, setup_g1: &SimulateSetupG1) -> Vec<G1Affine> {
    // f_i: coeffs[i], m = BLOB_ROW_N
    // left vector: f_{m-1}, 0, ..., 0 (totally m-1 0's), f_{m-1}, f_0, f_1, ..., f_{m-2}
    // right vector: setup_g1[m-1], ..., setup_g1[0], 0, ..., 0 (totally m G1 0's)
    // ifft(fft(left vector) element-wise-product fft(right vector)), take the first m elements as h
    // result = fft(h)
    let domain_blob_row_n = Radix2EvaluationDomain::<Scalar>::new(BLOB_ROW_N).unwrap();
    let domain_blob_row_n2 = Radix2EvaluationDomain::<Scalar>::new(BLOB_ROW_N2).unwrap();

    let mut right: Vec<G1Projective> = setup_g1[..BLOB_ROW_N].iter().map(|x| x.clone().into_group()).collect();
    right.reverse();
    right.extend(vec![G1Projective::zero(); BLOB_ROW_N]);
    domain_blob_row_n2.fft_in_place(&mut right);

    let mut left: Vec<Scalar> = vec![Scalar::zero(); BLOB_ROW_N + 1];
    left[0] = coeffs[BLOB_ROW_N - 1].clone();
    left[BLOB_ROW_N] = coeffs[BLOB_ROW_N - 1].clone();
    left.extend(coeffs[..BLOB_ROW_N - 1].to_vec());
    domain_blob_row_n2.fft_in_place(&mut left);
    
    let mut h: Vec<G1Projective> = right.iter().zip(left.iter())
        .map(|(iright, ileft)| *iright * ileft)
        .collect();
    domain_blob_row_n2.ifft_in_place(&mut h);
    h.truncate(BLOB_ROW_N); // here h is h
    domain_blob_row_n.fft_in_place(&mut h);
    h.into_iter().map(|x| x.into_affine()).collect::<Vec<G1Affine>>()
}

pub fn encoded_to_KZG(encoded: EncodedBlobEncoded, setup_g1: &SimulateSetupG1) -> Result<EncodedBlobKZG, String> { //EncodedBlob {
    // KZG
    if setup_g1.len() < std::cmp::max(BLOB_COL_N, BLOB_ROW_N2) {
        return Err(format!("The degree of setup_g1 {} is less than required {}", setup_g1.len(), std::cmp::max(BLOB_COL_N, BLOB_ROW_N2)));
    }
    // commit for each row of encoded
    let row_commitments = encoded_to_row_commitments(&encoded, setup_g1);
    // commit for row_commitments
    let mut row_commitments_scalars = row_commitments
        .iter()
        .map(|g1| g1_to_scalar(g1))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("SerializationError in g1_to_scalar(), err = {}", err))?;
    let domain_blob_row_n2 = Radix2EvaluationDomain::<Scalar>::new(BLOB_ROW_N2).unwrap();
    domain_blob_row_n2.ifft_in_place(&mut row_commitments_scalars);
    let da_commitment = coeffs_to_commitment(&row_commitments_scalars, setup_g1);
    let da_proofs = coeffs_to_multi_proof(&row_commitments_scalars, setup_g1);
    Ok(EncodedBlobKZG {
        encoded,
        row_commitments,
        da_commitment,
        da_proofs
    })
    //raw_blob
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::time::Instant;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use test_case::test_case;
    use ark_bn254::{Fr as Scalar, G1Affine};
    use ark_ff::{Field, MontConfig, UniformRand};
    use ark_std::rand::thread_rng;
    #[test]
    fn test_bytes_to_scalar() {
        let chunk = [0u8; 31];
        let scalar = <Scalar as Field>::from_random_bytes(&chunk).unwrap();
        dbg!(MontConfig::into_bigint(scalar));
    }
    #[test]
    fn test_g1_to_scalar() {
        let mut rng = thread_rng();
        let g1 = G1Affine::rand(&mut rng);
        let scalar = g1_to_scalar(&g1);
    }
    #[test_case(0 => Ok(()); "zero sized data")]
    #[test_case(1 => Ok(()); "one sized data")]
    #[test_case(12345565 => Ok(()); "normal sized data")]
    #[test_case(RAW_UNIT * BLOB_ROW_N * BLOB_COL_N => Ok(()); "exact sized data")]
    #[test_case(RAW_UNIT * BLOB_ROW_N * BLOB_COL_N + 1 => Err(format!("Input byte slice length {} exceeds the required length {} for RawData.", RAW_UNIT * BLOB_ROW_N * BLOB_COL_N + 1, RAW_UNIT * BLOB_ROW_N * BLOB_COL_N)); "overflow sized data")]
    fn benchmark_batcher(num_bytes: usize) -> Result<(), String> {
        // generate random original data with {num_bytes} bytes
        let seed = 22u64;
        let mut rng = StdRng::seed_from_u64(seed);
        let mut data = vec![0u8; num_bytes];
        rng.fill(&mut data[..]);

        // zero-padding original data to raw_data
        let raw_data: RawData = RawData::try_from(data.as_slice())?;
        
        // raw_data_to_raw_blob
        let start = Instant::now();
        let raw_blob = raw_data_to_raw_blob(&raw_data);
        let duration = start.elapsed().as_millis();
        println!("Time taken for raw_data_to_raw_blob: {:?}ms with original {} bytes and raw_data {} bytes", duration, num_bytes, raw_data.len());
        
        // encode
        let start = Instant::now();
        let encoded: EncodedBlobEncoded = raw_blob_to_encoded(&raw_blob);
        let duration = start.elapsed().as_millis();
        println!("Time taken for RS_encode: {:?}ms with raw_data {} bytes", duration, raw_data.len());

        // KZG
        let setup_g1 = SimulateSetupG1::sim_load();
        let start = Instant::now();
        let encoded_blob_KZG = encoded_to_KZG(encoded, &setup_g1).unwrap();
        let duration = start.elapsed().as_millis();
        println!("Time taken for encoded_to_KZG: {:?}ms with raw_data {} bytes", duration, raw_data.len());
        
        // Merkle
        Ok(())
    }
}