use std::mem;

use crate::types::*;
use ark_ec::{bn::Bn, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_std::iterable::Iterable;
use ethereum_types::H256;
use ark_bn254::{Fr as Scalar, G1Affine, G1Projective};
use ark_ff::{fields::Field, MontConfig};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
//use once_cell::sync::Lazy;
// use transpose::transpose;

fn raw_unit_to_scalar(chunk: &[u8]) -> Scalar {
    // <Scalar as PrimeField>::from_le_bytes_mod_order(&chunk) // 76ms
    // safety: chunk.len() == 31 for ark_bn254
    <Scalar as Field>::from_random_bytes(&chunk).unwrap() // 33 ms
}

pub fn raw_data_to_raw_blob(data: &RawData) -> Result<RawBlob, String> {
    let raw_blob_1d: Vec<_> = data.chunks(RAWUNIT).map(raw_unit_to_scalar).collect();
    let raw_blob_1d: Box<[Scalar; BLOBN * BLOBN]> = raw_blob_1d.into_boxed_slice().try_into().unwrap();
    
    if mem::size_of::<[Scalar; BLOBN * BLOBN]>() != mem::size_of::<[[Scalar; BLOBN]; BLOBN]>() || mem::align_of::<[Scalar; BLOBN * BLOBN]>() != mem::align_of::<[[Scalar; BLOBN]; BLOBN]>()
    {
        //compile_error!("Invalid unsafe transmute in raw_data_to_raw_blob().");
        return Err(format!("Invalid unsafe transmute in raw_data_to_raw_blob()."));
    }
    let raw_blob_2d: RawBlob = unsafe {
        std::mem::transmute(raw_blob_1d)
    };
    Ok(raw_blob_2d)
}

pub fn single_fft(coeffs: &mut Vec<Scalar>, fft_domain: Radix2EvaluationDomain::<Scalar>) -> () {
    fft_domain.fft_in_place(coeffs);
}

pub fn single_ifft(evals: &mut Vec<Scalar>, ifft_domain: Radix2EvaluationDomain::<Scalar>) -> () {
    ifft_domain.ifft_in_place(evals);
}

pub fn single_rs_encode(evals: &mut Vec<Scalar>, ifft_domain: Radix2EvaluationDomain::<Scalar>, fft_domain: Radix2EvaluationDomain::<Scalar>) -> () {
    single_ifft(evals, ifft_domain);
    single_fft(evals, fft_domain);
}

// rs_encode for each row of matrix (in place)
pub fn rs_encode_blobn_cols(matrix: &mut Vec<Vec<Scalar>>) -> () {
    // all rows use the same ifft_domain and the same fft_domain
    let ifft_domain = Radix2EvaluationDomain::<Scalar>::new(BLOBN).unwrap();
    let fft_domain = Radix2EvaluationDomain::<Scalar>::new(BLOBN << 1).unwrap();
    // RS encode for each row of matrix
    matrix.iter_mut().for_each(|column_data| {
        single_rs_encode(column_data, ifft_domain, fft_domain);
    });
}

/// RS encode for each col of raw_blob
pub fn raw_blob_to_encoded_blob_encode(raw_blob: &RawBlob) -> Result<EncodedBlobEncoded, String> {
    // transpose raw_blob
    let mut raw_blob_transpose: Vec<Vec<Scalar>> = (0..BLOBN)
        .map(|col_index| raw_blob.iter().map(|row| row[col_index].clone()).collect::<Vec<Scalar>>())
        .collect();
    // RS encode for each row of raw_blob_transpose, i.e., for each col of raw_blob
    rs_encode_blobn_cols(&mut raw_blob_transpose);
    // transpose back and flat
    let encoded_flatten: Vec<Scalar> = (0..BLOBN << 1)
        .flat_map(|row_index| raw_blob_transpose.iter().map(|col| col[row_index].clone()).collect::<Vec<Scalar>>())
        .collect();
    // vec_1d to Box_2d
    let encoded_flatten: Box<[Scalar; BLOBN * BLOBN * 2]> = encoded_flatten.into_boxed_slice().try_into().unwrap();
    if mem::size_of::<[Scalar; BLOBN * BLOBN * 2]>() != mem::size_of::<[[Scalar; BLOBN]; BLOBN * 2]>() || mem::align_of::<[Scalar; BLOBN * BLOBN * 2]>() != mem::align_of::<[[Scalar; BLOBN]; BLOBN * 2]>()
    {
        //compile_error!("Invalid unsafe transmute in raw_blob_to_encoded_blob_encode().");
        return Err(format!("Invalid unsafe transmute in raw_blob_to_encoded_blob_encode()."));
    }
    let encoded: EncodedBlobEncoded = unsafe {
        std::mem::transmute(encoded_flatten)
    };
    Ok(encoded)
}

pub fn single_commit(_evals: &[Scalar; BLOBN], ifft_domain: Radix2EvaluationDomain::<Scalar>, setup_g1: &SimulateSetupG1) -> G1Affine {
    let mut evals = _evals.to_vec();
    single_ifft(&mut evals, ifft_domain);
    let coeffs_repr: Vec<_> = evals.into_iter().map(|x| MontConfig::into_bigint(x)).collect();
    G1Projective::msm_bigint(setup_g1, &coeffs_repr).into_affine()
}

/// KZG commit for each row of raw_blob
pub fn raw_blob_to_encoded_blob_commit(raw_blob: &RawBlob, setup_g1: &SimulateSetupG1) -> RowCommitments {
    // all rows use the same ifft_domain
    let ifft_domain = Radix2EvaluationDomain::<Scalar>::new(BLOBN).unwrap();
    // KZG commitment
    let row_commitments: Vec<_> = raw_blob
        .iter()
        .map(|row| single_commit(&row, ifft_domain, setup_g1))
        .collect();
    let row_commitments: [G1Affine; BLOBN] = row_commitments.try_into().unwrap();
    RowCommitments(row_commitments)
}


pub fn rs_encode_blobn_cols_g1(row_commitments: &RowCommitments) -> RowCommitmentsEncoded{
    let mut evals_g1: Vec<_> = row_commitments.iter().map(|x| x.into_group()).collect();
    let ifft_domain = Radix2EvaluationDomain::<Scalar>::new(BLOBN).unwrap();
    let fft_domain = Radix2EvaluationDomain::<Scalar>::new(BLOBN << 1).unwrap();
    ifft_domain.ifft_in_place(&mut evals_g1);
    fft_domain.fft_in_place(&mut evals_g1);
    let row_commitments_encoded: [G1Affine; BLOBN << 1] = evals_g1
        .iter()
        .map(|x| x.into_affine())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    RowCommitmentsEncoded(row_commitments_encoded)
}

pub fn raw_blob_to_encoded_blob(raw_blob: &RawBlob, setup_g1: &SimulateSetupG1) -> Result<(), String> { //EncodedBlob {
    // RS encode for each col of raw_blob
    let encoded: EncodedBlobEncoded = raw_blob_to_encoded_blob_encode(raw_blob).unwrap();
    // commitment for each row of raw_blob
    let row_commitments = raw_blob_to_encoded_blob_commit(raw_blob, setup_g1);
    // RS encode for row_commitments
    let row_commitments_encoded = rs_encode_blobn_cols_g1(&row_commitments);
    Ok(())
    //raw_blob
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::time::Instant;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use test_case::test_case;
    #[test_case(0 => Ok(()); "zero sized data")]
    #[test_case(1 => Ok(()); "one sized data")]
    #[test_case(12345565 => Ok(()); "normal sized data")]
    #[test_case(RAWUNIT * BLOBN * BLOBN => Ok(()); "exact sized data")]
    #[test_case(RAWUNIT * BLOBN * BLOBN + 1 => Err(format!("Input byte slice length {} exceeds the required length {} for RawData.", RAWUNIT * BLOBN * BLOBN + 1, RAWUNIT * BLOBN * BLOBN)); "overflow sized data")]
    fn benchmark_batcher(num_bytes: usize) -> Result<(), String> {
        // generate random original data with {num_bytes} bytes
        let seed = 22u64;
        let mut rng = StdRng::seed_from_u64(seed);
        let mut data = vec![0u8; num_bytes];
        rng.fill(&mut data[..]);

        // padding original data to raw_data
        let raw_data: RawData = RawData::try_from(data.as_slice())?;
        
        // raw_data_to_raw_blob
        let start = Instant::now();
        let raw_blob = raw_data_to_raw_blob(&raw_data).unwrap();
        let duration = start.elapsed().as_millis();
        println!("Time taken for raw_data_to_raw_blob: {:?}ms with original {} bytes and raw_data {} bytes", duration, num_bytes, raw_data.len());
        
        // obtain setup_g1
        let setup_g1 = SimulateSetupG1::sim_load();
        // raw_blob_to_encoded_blob
        let start = Instant::now();
        let encoded_blob = raw_blob_to_encoded_blob(&raw_blob, &setup_g1).unwrap();
        let duration = start.elapsed().as_millis();
        println!("Time taken for raw_blob_to_encoded_blob: {:?}ms with raw_data {} bytes", duration, raw_data.len());
        
        Ok(())
    }
}