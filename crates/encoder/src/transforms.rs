use std::collections::VecDeque;

use crate::types::*;
use amt::{EncoderContext, PowerTau};
use ark_bn254::{Bn254, Fr as Scalar, G1Affine, G1Projective, G2Projective};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, VariableBaseMSM,
};
use ark_ff::{fields::Field, BigInteger, MontConfig, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalSerialize, SerializationError};
use ark_std::{iterable::Iterable, Zero};
use binary_merkle_tree::{merkle_proof, merkle_root, verify_proof};
use ethereum_types::H256;
use hash_db::Hasher;
use keccak_hasher::KeccakHasher;

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Keccak256;
impl Hasher for Keccak256 {
    type Out = H256;

    type StdHasher = <KeccakHasher as Hasher>::StdHasher;

    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> Self::Out {
        H256(KeccakHasher::hash(x))
    }
}

//use once_cell::sync::Lazy;
// use transpose::transpose;
pub type PE = Bn254;

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
        .map(|col_index| {
            (0..BLOB_ROW_N)
                .map(|row_index| raw_blob[(row_index << BLOB_COL_LOG) + col_index].clone())
                .collect::<Vec<Scalar>>()
        })
        .collect();
    // RS encode for each row of raw_blob_transpose, i.e., for each col of raw_blob
    rs_encode_blobn_cols(&mut raw_blob_transpose);
    // transpose back and flat
    let encoded_flatten: Vec<Scalar> = (0..BLOB_ROW_N << 1)
        .flat_map(|row_index| {
            raw_blob_transpose
                .iter()
                .map(|col| col[row_index].clone())
                .collect::<Vec<Scalar>>()
        })
        .collect();
    EncodedBlobScalars(encoded_flatten)
}

/// AMT
pub fn raw_blob_to_encoded_amt(
    raw_blob: &RawBlob,
    encoder_amt: &EncoderContext<PE>,
) -> EncodedBlobHalves<PE, BLOB_COL_LOG, BLOB_ROW_LOG> {
    let (primary_blob, coset_blob) =
        encoder_amt.process_blob::<BLOB_COL_LOG, BLOB_ROW_LOG>(raw_blob.as_slice());
    EncodedBlobHalves {
        primary: primary_blob,
        coset: coset_blob,
    }
}

pub fn coeffs_to_commitment(coeffs: &Vec<Scalar>, pp: &PowerTau<PE>) -> G1Affine {
    let coeffs_repr: Vec<_> = coeffs.iter().map(|x| MontConfig::into_bigint(*x)).collect();
    G1Projective::msm_bigint(&pp.0[..coeffs_repr.len()], &coeffs_repr).into_affine()
    //G1Projective::msm(&pp.0[..coeffs.len()], &coeffs).unwrap().into_affine()
}

pub fn evals_to_commitment(
    _evals: &[Scalar],
    domain: Radix2EvaluationDomain<Scalar>,
    pp: &PowerTau<PE>,
) -> G1Affine {
    let mut evals = _evals.to_vec();
    domain.ifft_in_place(&mut evals);
    coeffs_to_commitment(&evals, pp)
}

/// KZG commit for each row of raw_blob
pub fn encoded_to_row_commitments(
    encoded: &EncodedBlobScalars,
    pp: &PowerTau<PE>,
) -> RowCommitments {
    // all rows use the same domain_blob_col_n
    let domain_blob_col_n = Radix2EvaluationDomain::<Scalar>::new(BLOB_COL_N).unwrap();
    // KZG commitment
    let row_commitments: Vec<_> = encoded
        .chunks(BLOB_COL_N)
        .map(|row| evals_to_commitment(row, domain_blob_col_n, pp))
        .collect();
    RowCommitments(row_commitments)
}

pub fn g1_to_scalar(g1: &G1Affine) -> Result<Scalar, SerializationError> {
    let mut compressed_bytes = Vec::new();
    g1.serialize_compressed(&mut compressed_bytes)?;
    Ok(<Scalar as PrimeField>::from_le_bytes_mod_order(
        &compressed_bytes,
    ))
}

pub fn coeffs_to_proof_trivial(coeffs: &Vec<Scalar>, pp: &PowerTau<PE>) -> Vec<G1Affine> {
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
            let proof_i = coeffs_to_commitment(&quotient_coeffs, pp);
            //dbg!(i);
            //assert_eq!(proof_0, h[i].into_affine());
            proof_i
        })
        .collect::<Vec<G1Affine>>()
}

pub fn coeffs_to_proof_multiple(coeffs: &Vec<Scalar>, pp: &PowerTau<PE>) -> Vec<G1Affine> {
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

    let mut right: Vec<G1Projective> = pp.0[..num_coeffs]
        .iter()
        .map(|x| x.clone().into_group())
        .collect();
    right.reverse();
    right.extend(vec![G1Projective::zero(); num_coeffs]);
    domain_blob_row_n4.fft_in_place(&mut right);

    let mut left: Vec<Scalar> = vec![Scalar::zero(); num_coeffs + 1];
    left[0] = coeffs[num_coeffs - 1].clone();
    left[num_coeffs] = coeffs[num_coeffs - 1].clone();
    left.extend(coeffs[..num_coeffs - 1].to_vec());
    domain_blob_row_n4.fft_in_place(&mut left);

    let mut h: Vec<G1Projective> = right
        .iter()
        .zip(left.iter())
        .map(|(iright, ileft)| *iright * ileft)
        .collect();
    domain_blob_row_n4.ifft_in_place(&mut h);
    h.truncate(num_coeffs); // here h is h

    // dbg!(num_coeffs);
    // for i in 0..num_coeffs {
    //     dbg!(i);
    //     let h_i: G1Projective = pp.0[..(num_coeffs - i)].iter().zip(coeffs[i..].iter()).map(|(ss, ff)| *ss * ff).sum();
    //     assert_eq!(h_i.into_affine(), h[i].into_affine());
    // }
    // // h_i = s_0 * f_i + s_1 * f_{i+1} + ... + s_{m-1-i} * f_{m-1}, i = 0, ..., m-1
    // // c_w_k = h_0 + h_1 * w^k + ... + h_{m-1} * w^{(m-1)k}

    // let c_w_0: G1Projective = h.iter().sum();
    // let c_w_1: G1Projective = h.iter().zip(domain_blob_row_n2.elements()).map(|(hh, ww)| *hh * ww).sum();

    domain_blob_row_n2.fft_in_place(&mut h);

    // assert_eq!(c_w_1.into_affine(), h[1].into_affine());
    // assert_eq!(c_w_0.into_affine(), h[0].into_affine());

    h.into_iter()
        .map(|x| x.into_affine())
        .collect::<Vec<G1Affine>>()
}

pub fn encoded_to_kzg(
    encoded: EncodedBlobScalars,
    pp: &PowerTau<PE>,
) -> Result<EncodedBlobKZG, String> {
    //EncodedBlob {
    if pp.0.len() < std::cmp::max(BLOB_COL_N, BLOB_ROW_N2) {
        return Err(format!(
            "The degree of setup_g1 {} is less than required {}",
            pp.0.len(),
            std::cmp::max(BLOB_COL_N, BLOB_ROW_N2)
        ));
    }
    // commit for each row of encoded
    let row_commitments = encoded_to_row_commitments(&encoded, pp);
    // commit for row_commitments & obtain proofs
    let mut row_commitments_scalars = row_commitments
        .iter()
        .map(|g1| g1_to_scalar(g1))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("SerializationError in g1_to_scalar(), err = {}", err))?;
    let domain_blob_row_n2 = Radix2EvaluationDomain::<Scalar>::new(BLOB_ROW_N2).unwrap();
    domain_blob_row_n2.ifft_in_place(&mut row_commitments_scalars);
    let da_commitment = coeffs_to_commitment(&row_commitments_scalars, pp);
    //let da_proofs_trivial = coeffs_to_proof_trivial(&row_commitments_scalars, pp);
    let da_proofs = coeffs_to_proof_multiple(&row_commitments_scalars, pp);
    //dbg!(da_commitment);
    //dbg!(&da_proofs_trivial);
    //dbg!(&da_proofs);

    Ok(EncodedBlobKZG {
        encoded,
        row_commitments,
        da_commitment,
        da_proofs, //: da_proofs_trivial
    })
}

// Return true: proof is correct; false: not.
pub fn verify_kzg(
    row_commitment_scalar: Scalar,
    da_commitment: G1Affine,
    da_proof: G1Affine,
    domain: Scalar,
    pp: &PowerTau<PE>,
) -> bool {
    let h: G2Projective = pp.1[0].into_group();
    let zs2: G2Projective = pp.1[1].into_group() - pp.1[0] * domain;
    let is1: G1Projective = pp.0[0] * row_commitment_scalar;
    // assert_eq!(pp.0[0], G1Affine::generator());
    // assert_eq!(pp.1[0], G2Affine::generator());
    // e(da_proof, zs2) = e(da_commitment - is1, h)
    let e_proof: PairingOutput<Bn254> = Pairing::pairing(da_proof, zs2);
    let e_commitment: PairingOutput<Bn254> = Pairing::pairing(da_commitment.into_group() - is1, h);
    e_proof == e_commitment
}

pub fn scalar_to_h256(scalar: Scalar) -> Result<H256, String> {
    let bytes: Vec<u8> = MontConfig::into_bigint(scalar).to_bytes_le();
    if bytes.len() != 32 {
        return Err(format!(
            "The number of bytes representing Scalar {} is not 32 but {}",
            scalar,
            bytes.len()
        ));
    }
    Ok(H256::from_slice(&bytes))
}

pub fn encoded_blob_scalars_to_h256s(encoded: &Vec<Scalar>) -> Result<Vec<H256>, String> {
    let encoded_h256s: Vec<H256> = encoded
        .iter()
        .map(|x| scalar_to_h256(*x))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(encoded_h256s)
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
        data_root,
    }
}

pub fn data_to_encoded_blob_amt(
    raw_data: &RawData,
    pp: &PowerTau<PE>,
    encoder_amt: &EncoderContext<PE>,
) -> Result<EncodedBlobAMT<PE, BLOB_COL_LOG, BLOB_ROW_LOG>, String> {
    // raw_data_to_raw_blob
    let raw_blob = raw_data_to_raw_blob(&raw_data);
    // encode
    let encoded_amt = raw_blob_to_encoded_amt(&raw_blob, encoder_amt);
    let encoded = EncodedBlobScalars(
        [
            encoded_amt.primary.blob.to_vec(),
            encoded_amt.coset.blob.to_vec(),
        ]
        .concat(),
    );
    // KZG
    let encoded_blob_kzg = encoded_to_kzg(encoded, pp).unwrap();
    // prepare H256 for Merkle
    let encoded_h256 =
        EncodedBlobH256s(encoded_blob_scalars_to_h256s(&encoded_blob_kzg.encoded).unwrap());
    // Merkle
    let encoded_blob_merkle: EncodedBlobMerkle = encoded_h256s_to_merkle(encoded_h256);
    // integrate blob
    Ok(EncodedBlobAMT {
        amt: encoded_amt,
        kzg: encoded_blob_kzg,
        merkle: encoded_blob_merkle,
    })
}

pub fn data_to_encoded_blob(data: &[u8], pp: &PowerTau<PE>) -> Result<EncodedBlob, String> {
    // zero-padding original data to raw_data
    let raw_data: RawData = RawData::try_from(data)?;
    // raw_data_to_raw_blob
    let raw_blob = raw_data_to_raw_blob(&raw_data);
    // encode
    let encoded: EncodedBlobScalars = raw_blob_to_encoded(&raw_blob);
    // KZG
    let encoded_blob_kzg = encoded_to_kzg(encoded, pp).unwrap();
    // prepare H256 for Merkle
    let encoded_h256 =
        EncodedBlobH256s(encoded_blob_scalars_to_h256s(&encoded_blob_kzg.encoded).unwrap());
    // Merkle
    let encoded_blob_merkle: EncodedBlobMerkle = encoded_h256s_to_merkle(encoded_h256);
    // integrate blob
    Ok(EncodedBlob {
        kzg: encoded_blob_kzg,
        merkle: encoded_blob_merkle,
    })
}

pub fn encoded_blob_to_slice(
    encoded_blob: &EncodedBlob,
    index: usize,
) -> Result<EncodedSlice, String> {
    if index >= BLOB_ROW_N2 {
        // || index < 0 {
        return Err(format!(
            "Request with overflow index {}, while index must < {}",
            index, BLOB_ROW_N2
        ));
    }
    let start_index_2d: usize = index << BLOB_COL_LOG;
    let end_index_2d: usize = start_index_2d + BLOB_COL_N;
    let kzg_slice = EncodedSliceKZG {
        encoded: encoded_blob.kzg.encoded[start_index_2d..end_index_2d].to_vec(),
        row_commitment: encoded_blob.kzg.row_commitments[index],
        da_commitment: encoded_blob.kzg.da_commitment,
        da_proof: encoded_blob.kzg.da_proofs[index],
    };
    let merkle_slice = EncodedSliceMerkle {
        encoded: encoded_blob.merkle.encoded[start_index_2d..end_index_2d].to_vec(),
        merkle_proof: merkle_proof::<Keccak256, _, _>(
            encoded_blob.merkle.row_merkle_roots.clone(),
            index,
        ),
    };
    Ok(EncodedSlice {
        index,
        kzg: kzg_slice,
        merkle: merkle_slice,
    })
}

pub fn encoded_blob_to_slice_amt(
    encoded_blob: &EncodedBlobAMT<PE, BLOB_COL_LOG, BLOB_ROW_LOG>,
    index: usize,
) -> Result<EncodedSliceAMT<PE, BLOB_COL_LOG, BLOB_ROW_LOG>, String> {
    if index >= BLOB_ROW_N2 {
        // || index < 0 {
        return Err(format!(
            "Request with overflow index {}, while index must < {}",
            index, BLOB_ROW_N2
        ));
    }
    let start_index_2d: usize = index << BLOB_COL_LOG;
    let end_index_2d: usize = start_index_2d + BLOB_COL_N;
    let kzg_slice = EncodedSliceKZG {
        encoded: encoded_blob.kzg.encoded[start_index_2d..end_index_2d].to_vec(),
        row_commitment: encoded_blob.kzg.row_commitments[index],
        da_commitment: encoded_blob.kzg.da_commitment,
        da_proof: encoded_blob.kzg.da_proofs[index],
    };
    let merkle_slice = EncodedSliceMerkle {
        encoded: encoded_blob.merkle.encoded[start_index_2d..end_index_2d].to_vec(),
        merkle_proof: merkle_proof::<Keccak256, _, _>(
            encoded_blob.merkle.row_merkle_roots.clone(),
            index,
        ),
    };
    let amt_slice = {
        if index < BLOB_ROW_N {
            EncodedSliceHalves {
                commitment: encoded_blob.amt.primary.commitment,
                row: encoded_blob.amt.primary.get_row(index),
            }
        } else {
            EncodedSliceHalves {
                commitment: encoded_blob.amt.coset.commitment,
                row: encoded_blob.amt.coset.get_row(index - BLOB_ROW_N),
            }
        }
    };
    Ok(EncodedSliceAMT {
        index,
        amt: amt_slice,
        kzg: kzg_slice,
        merkle: merkle_slice,
    })
}

pub fn verify_slice(encoded_slice: &EncodedSlice, pp: &PowerTau<PE>) -> bool {
    // verify index
    if encoded_slice.index >= BLOB_ROW_N2
        || encoded_slice.index != encoded_slice.merkle.merkle_proof.leaf_index
    {
        // || index < 0 {
        return false;
    }
    // verify length
    if encoded_slice.merkle.merkle_proof.number_of_leaves != BLOB_ROW_N2 {
        return false;
    }
    // verify scalars_to_h256s
    let encoded_h256_try = encoded_blob_scalars_to_h256s(&encoded_slice.kzg.encoded);
    let encoded_h256 = match encoded_h256_try {
        Ok(data) => data,
        Err(_) => return false,
    };
    if encoded_h256 != encoded_slice.merkle.encoded {
        return false;
    }
    // verify KZG local
    let domain_blob_col_n = Radix2EvaluationDomain::<Scalar>::new(BLOB_COL_N).unwrap();
    let kzg_local = evals_to_commitment(&encoded_slice.kzg.encoded, domain_blob_col_n, pp);
    if kzg_local != encoded_slice.kzg.row_commitment {
        return false;
    }
    // verify KZG global
    let row_commitment_scalar_try = g1_to_scalar(&encoded_slice.kzg.row_commitment);
    let row_commitment_scalar = match row_commitment_scalar_try {
        Ok(data) => data,
        Err(_) => return false,
    };
    let domain_blob_row_n2 = Radix2EvaluationDomain::<Scalar>::new(BLOB_ROW_N2).unwrap();
    let domain: Scalar = domain_blob_row_n2
        .elements()
        .nth(encoded_slice.index)
        .unwrap();
    let verify_kzg_global = verify_kzg(
        row_commitment_scalar,
        encoded_slice.kzg.da_commitment,
        encoded_slice.kzg.da_proof,
        domain,
        pp,
    );
    if !verify_kzg_global {
        return false;
    }
    // verify Merkle local
    let row_merkle_root = merkle_root::<Keccak256, _>(encoded_slice.merkle.encoded.clone());
    if row_merkle_root != encoded_slice.merkle.merkle_proof.leaf {
        return false;
    }
    // verify Merkle global
    verify_proof::<Keccak256, _, _>(
        &encoded_slice.merkle.merkle_proof.root,
        encoded_slice.merkle.merkle_proof.proof.clone(),
        encoded_slice.merkle.merkle_proof.number_of_leaves,
        encoded_slice.merkle.merkle_proof.leaf_index,
        &encoded_slice.merkle.merkle_proof.leaf,
    )
}

pub fn verify_slice_amt(
    encoded_slice: &EncodedSliceAMT<PE, BLOB_COL_LOG, BLOB_ROW_LOG>,
    pp: &PowerTau<PE>,
    encoder_amt: &EncoderContext<PE>,
) -> bool {
    // verify index
    if encoded_slice.index >= BLOB_ROW_N2
        || encoded_slice.index != encoded_slice.merkle.merkle_proof.leaf_index
    {
        // || index < 0 {
        return false;
    }
    // verify amt row index
    if encoded_slice.index < BLOB_ROW_N {
        if encoded_slice.index != encoded_slice.amt.row.index {
            return false;
        }
    } else {
        if encoded_slice.index - BLOB_ROW_N != encoded_slice.amt.row.index {
            return false;
        }
    }
    // verify length
    if encoded_slice.merkle.merkle_proof.number_of_leaves != BLOB_ROW_N2 {
        return false;
    }
    // verify scalars_to_h256s
    let encoded_h256_try = encoded_blob_scalars_to_h256s(&encoded_slice.kzg.encoded);
    let encoded_h256 = match encoded_h256_try {
        Ok(data) => data,
        Err(_) => return false,
    };
    if encoded_h256 != encoded_slice.merkle.encoded {
        return false;
    }
    // verify amt
    let amt_try = {
        if encoded_slice.index < BLOB_ROW_N {
            encoded_slice
                .amt
                .row
                .verify(&encoder_amt.amt, encoded_slice.amt.commitment)
        } else {
            encoded_slice
                .amt
                .row
                .verify(&encoder_amt.coset_amt, encoded_slice.amt.commitment)
        }
    };
    match amt_try {
        Err(_) => return false,
        _ => (),
    }
    // verify KZG local
    let domain_blob_col_n = Radix2EvaluationDomain::<Scalar>::new(BLOB_COL_N).unwrap();
    let kzg_local = evals_to_commitment(&encoded_slice.kzg.encoded, domain_blob_col_n, pp);
    if kzg_local != encoded_slice.kzg.row_commitment {
        return false;
    }
    // verify KZG global
    let row_commitment_scalar_try = g1_to_scalar(&encoded_slice.kzg.row_commitment);
    let row_commitment_scalar = match row_commitment_scalar_try {
        Ok(data) => data,
        Err(_) => return false,
    };
    let domain_blob_row_n2 = Radix2EvaluationDomain::<Scalar>::new(BLOB_ROW_N2).unwrap();
    let domain: Scalar = domain_blob_row_n2
        .elements()
        .nth(encoded_slice.index)
        .unwrap();
    let verify_kzg_global = verify_kzg(
        row_commitment_scalar,
        encoded_slice.kzg.da_commitment,
        encoded_slice.kzg.da_proof,
        domain,
        pp,
    );
    if !verify_kzg_global {
        return false;
    }
    // verify Merkle local
    let row_merkle_root = merkle_root::<Keccak256, _>(encoded_slice.merkle.encoded.clone());
    if row_merkle_root != encoded_slice.merkle.merkle_proof.leaf {
        return false;
    }
    // verify Merkle global
    verify_proof::<Keccak256, _, _>(
        &encoded_slice.merkle.merkle_proof.root,
        encoded_slice.merkle.merkle_proof.proof.clone(),
        encoded_slice.merkle.merkle_proof.number_of_leaves,
        encoded_slice.merkle.merkle_proof.leaf_index,
        &encoded_slice.merkle.merkle_proof.leaf,
    )
}

#[cfg(test)]
mod tests {
    use crate::*;
    use amt::{AMTParams, EncoderContext, PowerTau};
    use ark_bn254::{Bn254, Fr as Scalar, G1Affine, G2Affine};
    use ark_ff::{Field, MontConfig, UniformRand};
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_std::rand::thread_rng;
    use binary_merkle_tree::{merkle_proof, verify_proof};
    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::time::Instant;
    use test_case::test_case;

    const TEST_LEVEL: usize = 8;
    const TEST_LENGTH: usize = 1 << TEST_LEVEL;
    type PE = Bn254;
    static PP: Lazy<PowerTau<PE>> =
        Lazy::new(|| PowerTau::<PE>::from_dir("../amt/pp", TEST_LEVEL, true));

    static AMT: Lazy<AMTParams<PE>> = Lazy::new(|| AMTParams::from_pp(PP.clone(), false));

    static G1PP: Lazy<Vec<G1Affine>> =
        Lazy::new(|| PP.0.iter().copied().map(|x| G1Affine::from(x)).collect());

    static G2PP: Lazy<Vec<G2Affine>> =
        Lazy::new(|| PP.1.iter().copied().map(|x| G2Affine::from(x)).collect());

    static DOMAIN: Lazy<Radix2EvaluationDomain<Scalar>> =
        Lazy::new(|| Radix2EvaluationDomain::new(TEST_LENGTH).unwrap());

    static W: Lazy<Scalar> = Lazy::new(|| DOMAIN.group_gen);
    static ENCODER: Lazy<EncoderContext<PE>> =
        Lazy::new(|| EncoderContext::new("../amt/pp", BLOB_ROW_LOG + BLOB_COL_LOG, true));

    // #[test]
    // fn test_amt_setup() {}

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
    #[test_case(1234 => Ok(()); "normal sized data")]
    #[test_case(RAW_UNIT * BLOB_ROW_N * BLOB_COL_N => Ok(()); "exact sized data")]
    #[test_case(RAW_UNIT * BLOB_ROW_N * BLOB_COL_N + 1 => Err(format!("Input byte slice length {} exceeds the required length {} for RawData.", RAW_UNIT * BLOB_ROW_N * BLOB_COL_N + 1, RAW_UNIT * BLOB_ROW_N * BLOB_COL_N)); "overflow sized data")]
    fn test_batcher_encode_step_by_step(num_bytes: usize) -> Result<(), String> {
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
        println!(
            "Time taken for RS_encode: {:?}ms with original {} bytes and raw_data {} bytes",
            duration,
            num_bytes,
            raw_data.len()
        );

        // KZG
        let pp = &*PP;
        let start = Instant::now();
        let encoded_blob_kzg = encoded_to_kzg(encoded, &pp).unwrap();
        let duration = start.elapsed().as_millis();
        println!(
            "Time taken for encoded_to_KZG: {:?}ms with original {} bytes and raw_data {} bytes",
            duration,
            num_bytes,
            raw_data.len()
        );

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
                &pp,
            );
            assert!(verify_row_i);
        }

        // prepare H256 for Merkle
        let start = Instant::now();
        let encoded_h256 =
            EncodedBlobH256s(encoded_blob_scalars_to_h256s(&encoded_blob_kzg.encoded).unwrap());
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
            let proof_i =
                merkle_proof::<Keccak256, _, _>(encoded_blob_merkle.row_merkle_roots.clone(), i);
            let verify_i = verify_proof::<Keccak256, _, _>(
                &proof_i.root,
                proof_i.proof.clone(),
                proof_i.number_of_leaves,
                proof_i.leaf_index,
                &proof_i.leaf,
            );
            //let verify_i = verify_proof::<Keccak256, _, _>(&encoded_blob_merkle.data_root, proof_i.proof.clone(), BLOB_ROW_N2, i, &encoded_blob_merkle.row_merkle_roots[i]);
            assert!(verify_i);
        }
        let duration = start.elapsed().as_millis();
        println!("Time taken for prove and verify merkle: {:?}ms with original {} bytes and raw_data {} bytes", duration, num_bytes, raw_data.len());

        let encoded_blob = EncodedBlob {
            kzg: encoded_blob_kzg,
            merkle: encoded_blob_merkle,
        };
        Ok(())
    }

    #[test_case(0 => Ok(()); "pipeline: zero sized data")]
    #[test_case(1 => Ok(()); "pipeline: one sized data")]
    #[test_case(1234 => Ok(()); "pipeline: normal sized data")]
    #[test_case(RAW_UNIT * BLOB_ROW_N * BLOB_COL_N => Ok(()); "pipeline: exact sized data")]
    #[test_case(RAW_UNIT * BLOB_ROW_N * BLOB_COL_N + 1 => Err(format!("Input byte slice length {} exceeds the required length {} for RawData.", RAW_UNIT * BLOB_ROW_N * BLOB_COL_N + 1, RAW_UNIT * BLOB_ROW_N * BLOB_COL_N)); "pipeline: overflow sized data")]
    pub fn test_batcher_encode(num_bytes: usize) -> Result<(), String> {
        // generate random original data with {num_bytes} bytes
        let seed = 22u64;
        let mut rng = StdRng::seed_from_u64(seed);
        let mut data = vec![0u8; num_bytes];
        rng.fill(&mut data[..]);

        //let setup = SimulateSetup::sim_load();
        let pp = &*PP;
        //let encoded_blob = data_to_encoded_blob(data.as_slice(), &setup)?;
        let raw_data = data[..].try_into().unwrap();
        let encoded_blob = data_to_encoded_blob_amt(&raw_data, &pp, &ENCODER)?;

        Ok(())
    }

    #[test]
    fn test_batcher_slice_and_verify() {
        let seed = 22u64;
        let mut rng = StdRng::seed_from_u64(seed);
        let mut data = vec![0u8; RAW_UNIT * BLOB_ROW_N * BLOB_COL_N];
        rng.fill(&mut data[..]);

        let pp = &*PP;
        let encoded_blob = data_to_encoded_blob(data.as_slice(), pp).unwrap();

        let mut encoded_slice_0 = encoded_blob_to_slice(&encoded_blob, 0).unwrap();
        assert!(verify_slice(&encoded_slice_0, pp));
        encoded_slice_0.index = 1;
        assert!(!verify_slice(&encoded_slice_0, pp));
        encoded_slice_0.index = BLOB_ROW_N2;
        assert!(!verify_slice(&encoded_slice_0, pp));
        let mut encoded_slice_max = encoded_blob_to_slice(&encoded_blob, BLOB_ROW_N2 - 1).unwrap();
        assert!(verify_slice(&encoded_slice_max, pp));
        encoded_slice_max.merkle.merkle_proof.leaf_index = 1;
        assert!(!verify_slice(&encoded_slice_max, pp));
        encoded_blob_to_slice(&encoded_blob, BLOB_ROW_N2)
            .expect_err("Expected error for overflow row index");

        for index in 0..BLOB_ROW_N2 {
            assert!(verify_slice(
                &encoded_blob_to_slice(&encoded_blob, index).unwrap(),
                pp
            ));
        }
    }

    #[test]
    fn test_batcher_slice_and_verify_amt() {
        let seed = 22u64;
        let mut rng = StdRng::seed_from_u64(seed);
        let mut data = vec![0u8; RAW_UNIT * BLOB_ROW_N * BLOB_COL_N];
        rng.fill(&mut data[..]);

        // let setup = SimulateSetup::sim_load();
        let pp = &*PP;
        let raw_data = data[..].try_into().unwrap();
        let encoded_blob = data_to_encoded_blob_amt(&raw_data, pp, &ENCODER).unwrap();

        let mut encoded_slice_0 = encoded_blob_to_slice_amt(&encoded_blob, 0).unwrap();
        assert!(verify_slice_amt(&encoded_slice_0, pp, &ENCODER));
        encoded_slice_0.index = 1;
        assert!(!verify_slice_amt(&encoded_slice_0, pp, &ENCODER));
        encoded_slice_0.index = BLOB_ROW_N2;
        assert!(!verify_slice_amt(&encoded_slice_0, pp, &ENCODER));
        let mut encoded_slice_max =
            encoded_blob_to_slice_amt(&encoded_blob, BLOB_ROW_N2 - 1).unwrap();
        assert!(verify_slice_amt(&encoded_slice_max, pp, &ENCODER));
        encoded_slice_max.merkle.merkle_proof.leaf_index = 1;
        assert!(!verify_slice_amt(&encoded_slice_max, pp, &ENCODER));
        encoded_blob_to_slice_amt(&encoded_blob, BLOB_ROW_N2)
            .expect_err("Expected error for overflow row index");

        for index in 0..BLOB_ROW_N2 {
            assert!(verify_slice_amt(
                &encoded_blob_to_slice_amt(&encoded_blob, index).unwrap(),
                pp,
                &ENCODER
            ));
        }
    }
}
