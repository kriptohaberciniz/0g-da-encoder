use std::collections::VecDeque;

use crate::types::*;
use ark_ec::{pairing::{Pairing, PairingOutput}, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_std::{iterable::Iterable, Zero};
use ark_bn254::{Bn254, Fr as Scalar, G1Affine, G1Projective, G2Projective};
use ark_ff::{fields::Field, BigInteger, MontConfig, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalSerialize, SerializationError};
use binary_merkle_tree::merkle_root;
use ethereum_types::H256;
use sp_runtime::traits::Keccak256;
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
        domain_blob_row_n.ifft_in_place(column_data); // coeffs[i] = f_i; f_{BLOB_ROW_N} == 0
        domain_blob_row_n2.fft_in_place(column_data);
    });
}

/// RS encode for each col of raw_blob
pub fn raw_blob_to_encoded(raw_blob: &RawBlob) -> EncodedBlobScalars {
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
    EncodedBlobScalars(encoded_flatten)
}

pub fn coeffs_to_commitment(coeffs: &Vec<Scalar>, setup: &SimulateSetup) -> G1Affine {
    let coeffs_repr: Vec<_> = coeffs.iter().map(|x| MontConfig::into_bigint(*x)).collect();
    G1Projective::msm_bigint(&setup.setup_g1[..coeffs_repr.len()], &coeffs_repr).into_affine()
    //G1Projective::msm(&setup.setup_g1[..coeffs.len()], &coeffs).unwrap().into_affine()
}

pub fn evals_to_commitment(_evals: &[Scalar], domain: Radix2EvaluationDomain::<Scalar>, setup: &SimulateSetup) -> G1Affine {
    let mut evals = _evals.to_vec();
    domain.ifft_in_place(&mut evals);
    coeffs_to_commitment(&evals, setup)
}

/// KZG commit for each row of raw_blob
pub fn encoded_to_row_commitments(encoded: &EncodedBlobScalars, setup: &SimulateSetup) -> RowCommitments {
    // all rows use the same domain_blob_col_n
    let domain_blob_col_n = Radix2EvaluationDomain::<Scalar>::new(BLOB_COL_N).unwrap();
    // KZG commitment
    let row_commitments: Vec<_> = encoded
        .chunks(BLOB_COL_N)
        .map(|row| evals_to_commitment(row, domain_blob_col_n, setup))
        .collect();
    RowCommitments(row_commitments)
}

pub fn g1_to_scalar(g1: &G1Affine) -> Result<Scalar, SerializationError> {
    let mut compressed_bytes = Vec::new();
    g1.serialize_compressed(&mut compressed_bytes)?;
    Ok(<Scalar as PrimeField>::from_le_bytes_mod_order(&compressed_bytes))
}

pub fn coeffs_to_proof_trivial(coeffs: &Vec<Scalar>, setup: &SimulateSetup) -> Vec<G1Affine> {
    let num_coeffs = coeffs.len();
    let domain_blob_row_n2 = Radix2EvaluationDomain::<Scalar>::new(num_coeffs).unwrap();
    (0..num_coeffs)
        .map(|i| {
            let mut quotient_coeffs: Vec<Scalar> = vec![Scalar::zero(); num_coeffs];
            let domain: Scalar = domain_blob_row_n2.element(i);
            for t in (0..num_coeffs - 1).rev() {
                quotient_coeffs[t] = coeffs[t + 1] + domain * quotient_coeffs[t + 1];
                //dbg!(t);
                //dbg!(quotient_coeffs[t]);
            }
            //assert_eq!(quotient_coeffs[num_coeffs - 2], coeffs[num_coeffs - 1]);
            let proof_i = coeffs_to_commitment(&quotient_coeffs, setup);
            //dbg!(i);
            //assert_eq!(proof_0, h[i].into_affine());
            proof_i
        })
        .collect::<Vec<G1Affine>>()
}

pub fn coeffs_to_proof_multiple(coeffs: &Vec<Scalar>, setup: &SimulateSetup) -> Vec<G1Affine> {
    let mut coeffs: VecDeque<Scalar> = coeffs.clone().into();
    coeffs.pop_front();
    coeffs.push_back(Scalar::zero());
    let coeffs: Vec<Scalar> = coeffs.into();

    // f_i: coeffs[i], m = coeffs.len()
    // left vector: f_{m-1}, 0, ..., 0 (totally m-1 0's), f_{m-1}, f_0, f_1, ..., f_{m-2}
    // right vector: setup_g1[m-1], ..., setup_g1[0], 0, ..., 0 (totally m G1 0's)
    // ifft(fft(left vector) element-wise-product fft(right vector)), take the first m elements as h
    // result = fft(h)
    let num_coeffs = coeffs.len();
    let domain_blob_row_n2 = Radix2EvaluationDomain::<Scalar>::new(num_coeffs).unwrap();
    let domain_blob_row_n4 = Radix2EvaluationDomain::<Scalar>::new(num_coeffs << 1).unwrap();

    let mut right: Vec<G1Projective> = setup.setup_g1[..num_coeffs].iter().map(|x| x.clone().into_group()).collect();
    right.reverse();
    right.extend(vec![G1Projective::zero(); num_coeffs]);
    domain_blob_row_n4.fft_in_place(&mut right);

    let mut left: Vec<Scalar> = vec![Scalar::zero(); num_coeffs + 1];
    left[0] = coeffs[num_coeffs - 1].clone();
    left[num_coeffs] = coeffs[num_coeffs - 1].clone();
    left.extend(coeffs[..num_coeffs - 1].to_vec());
    domain_blob_row_n4.fft_in_place(&mut left);

    let mut h: Vec<G1Projective> = right.iter().zip(left.iter())
        .map(|(iright, ileft)| *iright * ileft)
        .collect();
    domain_blob_row_n4.ifft_in_place(&mut h);
    h.truncate(num_coeffs); // here h is h

    // dbg!(num_coeffs);
    // for i in 0..num_coeffs {
    //     dbg!(i);
    //     let h_i: G1Projective = setup.setup_g1[..(num_coeffs - i)].iter().zip(coeffs[i..].iter()).map(|(ss, ff)| *ss * ff).sum();
    //     assert_eq!(h_i.into_affine(), h[i].into_affine());
    // }
    // // h_i = s_0 * f_i + s_1 * f_{i+1} + ... + s_{m-1-i} * f_{m-1}, i = 0, ..., m-1
    // // c_w_k = h_0 + h_1 * w^k + ... + h_{m-1} * w^{(m-1)k}

    // let c_w_0: G1Projective = h.iter().sum();
    // let c_w_1: G1Projective = h.iter().zip(domain_blob_row_n2.elements()).map(|(hh, ww)| *hh * ww).sum();

    domain_blob_row_n2.fft_in_place(&mut h);

    // assert_eq!(c_w_1.into_affine(), h[1].into_affine());
    // assert_eq!(c_w_0.into_affine(), h[0].into_affine());

    h.into_iter().map(|x| x.into_affine()).collect::<Vec<G1Affine>>()
}

pub fn encoded_to_kzg(encoded: EncodedBlobScalars, setup: &SimulateSetup) -> Result<EncodedBlobKZG, String> { //EncodedBlob {
    if setup.setup_g1.len() < std::cmp::max(BLOB_COL_N, BLOB_ROW_N2) {
        return Err(format!("The degree of setup_g1 {} is less than required {}", setup.setup_g1.len(), std::cmp::max(BLOB_COL_N, BLOB_ROW_N2)));
    }
    // commit for each row of encoded
    let row_commitments = encoded_to_row_commitments(&encoded, setup);
    // commit for row_commitments & obtain proofs
    let mut row_commitments_scalars = row_commitments
        .iter()
        .map(|g1| g1_to_scalar(g1))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("SerializationError in g1_to_scalar(), err = {}", err))?;
    let domain_blob_row_n2 = Radix2EvaluationDomain::<Scalar>::new(BLOB_ROW_N2).unwrap();
    domain_blob_row_n2.ifft_in_place(&mut row_commitments_scalars);
    let da_commitment = coeffs_to_commitment(&row_commitments_scalars, setup);
    //let da_proofs_trivial = coeffs_to_proof_trivial(&row_commitments_scalars, setup);
    let da_proofs = coeffs_to_proof_multiple(&row_commitments_scalars, setup);
    //dbg!(da_commitment);
    //dbg!(&da_proofs_trivial);
    //dbg!(&da_proofs);

    Ok(EncodedBlobKZG {
        encoded,
        row_commitments,
        da_commitment,
        da_proofs//: da_proofs_trivial
    })
}

// Return true: proof is correct; false: not.
pub fn verify_kzg(
    row_commitment_scalar: Scalar, 
    da_commitment: G1Affine, 
    da_proof: G1Affine, 
    domain: Scalar, 
    setup: &SimulateSetup
) -> bool {
    let h: G2Projective = setup.setup_g2[0].into_group();
    let zs2: G2Projective = setup.setup_g2[1].into_group() - setup.setup_g2[0] * domain;
    let is1: G1Projective = setup.setup_g1[0] * row_commitment_scalar;
    // assert_eq!(setup.setup_g1[0], G1Affine::generator());
    // assert_eq!(setup.setup_g2[0], G2Affine::generator());
    // e(da_proof, zs2) = e(da_commitment - is1, h)
    let e_proof: PairingOutput<Bn254> = Pairing::pairing(da_proof, zs2);
    let e_commitment: PairingOutput<Bn254> = Pairing::pairing(da_commitment.into_group() - is1, h);
    e_proof == e_commitment
}

pub fn scalar_to_h256(scalar: Scalar) -> Result<H256, String> {
    let bytes: Vec<u8> = MontConfig::into_bigint(scalar).to_bytes_le();
    if bytes.len() != 32 {
        return Err(format!("The number of bytes representing Scalar {} is not 32 but {}", scalar, bytes.len()));
    }
    Ok(H256::from_slice(&bytes))
}

pub fn encoded_blob_scalars_to_h256s(encoded: &EncodedBlobScalars) -> Result<EncodedBlobH256s, String> {
    let encoded_h256s: Vec<H256> = encoded.iter()
        .map(|x| scalar_to_h256(*x))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EncodedBlobH256s(encoded_h256s))
}

pub fn encoded_h256s_to_merkle(encoded: EncodedBlobH256s) -> EncodedBlobMerkle {
    let row_merkle_roots: Vec<H256> = encoded
        .chunks(BLOB_COL_N)
        .map(|row| merkle_root::<Keccak256, _>(row))
        .collect();
    let data_root = merkle_root::<Keccak256, _>(row_merkle_roots.clone());
    EncodedBlobMerkle {
        encoded,
        row_merkle_roots,
        data_root
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::time::Instant;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use binary_merkle_tree::{merkle_proof, verify_proof};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp_runtime::traits::Keccak256;
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
    fn test_scalar_to_h256() {
        use ark_std::One;
        let one = Scalar::one();
        let one_h256 = scalar_to_h256(one).unwrap();
        let mut one_gt = [0u8; 32];
        one_gt[0] = 1;
        assert_eq!(one_h256.as_bytes(), one_gt);
    }
    #[test]
    fn test_g1_to_scalar() {
        let mut rng = thread_rng();
        let g1 = G1Affine::rand(&mut rng);
        let scalar = g1_to_scalar(&g1);
        println!("{:?}", scalar);
    }
    #[test_case(0 => Ok(()); "zero sized data")]
    #[test_case(1 => Ok(()); "one sized data")]
    #[test_case(12345565 => Ok(()); "normal sized data")]
    #[test_case(RAW_UNIT * BLOB_ROW_N * BLOB_COL_N => Ok(()); "exact sized data")]
    #[test_case(RAW_UNIT * BLOB_ROW_N * BLOB_COL_N + 1 => Err(format!("Input byte slice length {} exceeds the required length {} for RawData.", RAW_UNIT * BLOB_ROW_N * BLOB_COL_N + 1, RAW_UNIT * BLOB_ROW_N * BLOB_COL_N)); "overflow sized data")]
    fn test_batcher(num_bytes: usize) -> Result<(), String> {
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
        let encoded: EncodedBlobScalars = raw_blob_to_encoded(&raw_blob);
        let duration = start.elapsed().as_millis();
        println!("Time taken for RS_encode: {:?}ms with original {} bytes and raw_data {} bytes", duration, num_bytes, raw_data.len());

        // KZG
        let setup = SimulateSetup::sim_load();
        let start = Instant::now();
        let encoded_blob_kzg = encoded_to_kzg(encoded, &setup).unwrap();
        let duration = start.elapsed().as_millis();
        println!("Time taken for encoded_to_KZG: {:?}ms with original {} bytes and raw_data {} bytes", duration, num_bytes, raw_data.len());
        
        // verify KZG
        let domain_blob_row_n2 = Radix2EvaluationDomain::<Scalar>::new(BLOB_ROW_N2).unwrap();
        for i in 0..BLOB_ROW_N2 {
            let row_commitment = encoded_blob_kzg.row_commitments[i];
            let domain: Scalar = domain_blob_row_n2.elements().nth(i).unwrap();
            let verify_row_i = verify_kzg(
                g1_to_scalar(&row_commitment).unwrap(), 
                encoded_blob_kzg.da_commitment, 
                encoded_blob_kzg.da_proofs[i], 
                domain, 
                &setup);
            assert!(verify_row_i);
        }

        // prepare H256 for Merkle
        let start = Instant::now();
        let encoded_h256: EncodedBlobH256s = encoded_blob_scalars_to_h256s(&encoded_blob_kzg.encoded).unwrap();
        let duration = start.elapsed().as_millis();
        println!("Time taken for encoded_blob_scalars_to_h256s: {:?}ms with original {} bytes and raw_data {} bytes", duration, num_bytes, raw_data.len());

        // Merkle
        let start = Instant::now();
        let encoded_blob_merkle: EncodedBlobMerkle = encoded_h256s_to_merkle(encoded_h256);
        let duration = start.elapsed().as_millis();
        println!("Time taken for encoded_h256s_to_merkle: {:?}ms with original {} bytes and raw_data {} bytes", duration, num_bytes, raw_data.len());

        // verify Merkle
        let start = Instant::now();
        for i in 0..BLOB_ROW_N2 {
            let proof_i = merkle_proof::<Keccak256, _, _>(encoded_blob_merkle.row_merkle_roots.clone(), i);
            //let verify_i = verify_proof::<Keccak256, _, _>(&proof_i.root, proof_i.proof.clone(), BLOB_ROW_N2, proof_i.leaf_index, &proof_i.leaf);
            let verify_i = verify_proof::<Keccak256, _, _>(&encoded_blob_merkle.data_root, proof_i.proof.clone(), BLOB_ROW_N2, i, &encoded_blob_merkle.row_merkle_roots[i]);
            assert!(verify_i);
        }
        let duration = start.elapsed().as_millis();
        println!("Time taken for prove and verify merkle: {:?}ms with original {} bytes and raw_data {} bytes", duration, num_bytes, raw_data.len());
        Ok(())
    }
}