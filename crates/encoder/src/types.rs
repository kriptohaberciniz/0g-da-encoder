use std::{convert::identity, ops::{Deref, DerefMut}};

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand, One};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ethereum_types::H256;
use ark_bn254::{Fr as Scalar, G1Affine, G1Projective};

pub const RAW_UNIT: usize = 31;
pub const BLOB_UNIT: usize = 32;
pub const BLOB_ROW_LOG: usize = 10;
pub const BLOB_COL_LOG: usize = 11; // TODO
pub const BLOB_ROW_N: usize = 1 << BLOB_ROW_LOG;
pub const BLOB_ROW_N2: usize = BLOB_ROW_N << 1;
pub const BLOB_COL_N: usize = 1 << BLOB_COL_LOG;

#[repr(transparent)]
pub struct RawData(Vec<u8>); // RAW_UNIT * BLOB_ROW_N * BLOB_COL_N

impl Default for RawData {
    fn default() -> Self {
        RawData(vec![0u8; RAW_UNIT * BLOB_ROW_N * BLOB_COL_N])
    }
}

impl Deref for RawData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RawData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TryFrom<&[u8]> for RawData {
    type Error = String;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value_len = value.len();
        if value_len <= RAW_UNIT * BLOB_ROW_N * BLOB_COL_N {
            let mut array = vec![0u8; RAW_UNIT * BLOB_ROW_N * BLOB_COL_N];
            array[..value_len].copy_from_slice(&value[..]);
            Ok(RawData(array))
        } else {
            Err(format!("Input byte slice length {} exceeds the required length {} for RawData.", value.len(), RAW_UNIT * BLOB_ROW_N * BLOB_COL_N))
        }
    }
}


#[repr(transparent)]
pub struct RawBlob(pub Vec<Scalar>); // BLOB_ROW_N * BLOB_COL_N

impl Deref for RawBlob {
    type Target = Vec<Scalar>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RawBlob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(transparent)]
pub struct EncodedBlobEncoded(pub Vec<Scalar>); // BLOB_ROW_N2 * BLOB_COL_N

impl Deref for EncodedBlobEncoded {
    type Target = Vec<Scalar>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for EncodedBlobEncoded {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(transparent)]
pub struct RowCommitments(pub Vec<G1Affine>); // BLOB_ROW_N2

impl Deref for RowCommitments {
    type Target = Vec<G1Affine>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RowCommitments {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// impl Default for RowCommitments {
//     fn default() -> Self {
//         RowCommitments([G1Affine::default(); BLOBN])
//     }
// }

pub struct SimulateSetupG1(Vec<G1Affine>); // >= num_cols for each row's commitment
impl Deref for SimulateSetupG1 {
    type Target = Vec<G1Affine>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
pub const KZG_SETUP_N: usize = 1 << 11;
impl SimulateSetupG1 {
    pub fn sim_load() -> Self {
        use ark_std::rand::thread_rng;
        let mut rng = thread_rng();
        let s: Scalar = Scalar::rand(&mut rng);
        let all_s = [s; KZG_SETUP_N];
        let setup_g1: Vec<G1Affine> = all_s
            .iter()
            .scan(Scalar::one(), |state, &x| {
                *state *= x;
                Some(*state)
            })
            .map(|x: Scalar| (G1Affine::generator() * x).into_affine())
            .collect();
        Self(setup_g1)
    }
}


pub struct EncodedBlobKZG {
    pub encoded: EncodedBlobEncoded,
    pub row_commitments: RowCommitments,
    pub da_commitment: G1Affine,
    pub da_proofs: Vec<G1Affine>
    //row_merkle_roots: Vec<H256>, // BLOB_ROW_N
    //data_root: H256,
}

// pub struct  EncodedSlice {
//     slice: [H256; BLOBN],
//     row_coeff: [Scalar; BLOBN],
//     row_merkle_root: H256,
//     da_commitment: G1AffineCompressed,
//     merkle_proof: MerkleProof,
//     data_root: H256,
// }
