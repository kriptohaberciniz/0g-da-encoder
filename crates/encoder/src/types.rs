use std::{convert::identity, ops::{Deref, DerefMut}};

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand, One};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ethereum_types::H256;
use ark_bn254::{Fr as Scalar, G1Affine, G1Projective};

pub const RAWUNIT: usize = 31;
pub const BLOBUNIT: usize = 32;
pub const BLOBNLOG: usize = 10;
pub const BLOBN: usize = 1 << BLOBNLOG;

#[repr(transparent)]
pub struct RawData(Box<[u8; RAWUNIT * BLOBN * BLOBN]>);

impl Default for RawData {
    fn default() -> Self {
        RawData(vec![0u8; RAWUNIT * BLOBN * BLOBN].into_boxed_slice().try_into().unwrap())
    }
}

impl Deref for RawData {
    type Target = Box<[u8; RAWUNIT * BLOBN * BLOBN]>;

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
        if value_len <= RAWUNIT * BLOBN * BLOBN {
            let mut array = Box::new([0u8; RAWUNIT * BLOBN * BLOBN]);
            array[..value_len].copy_from_slice(&value[..]);
            Ok(RawData(array))
        } else {
            Err(format!("Input byte slice length {} exceeds the required length {} for RawData.", value.len(), RAWUNIT * BLOBN * BLOBN))
        }
    }
}


#[repr(transparent)]
pub struct RawBlob(Box<[[Scalar; BLOBN]; BLOBN]>);

impl Deref for RawBlob {
    type Target = Box<[[Scalar; BLOBN]; BLOBN]>;

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
pub struct EncodedBlobEncoded(Box<[[Scalar; BLOBN]; BLOBN * 2]>);

impl Deref for EncodedBlobEncoded {
    type Target = Box<[[Scalar; BLOBN]; BLOBN * 2]>;

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
pub struct RowCommitments(pub [G1Affine; BLOBN]); // num_rows_origin

impl Deref for RowCommitments {
    type Target = [G1Affine; BLOBN];

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
pub const KZGSETUPN: usize = BLOBN;
impl SimulateSetupG1 {
    pub fn sim_load() -> Self {
        use ark_std::rand::thread_rng;
        let mut rng = thread_rng();
        let s: Scalar = Scalar::rand(&mut rng);
        let all_s = [s; KZGSETUPN];
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

#[repr(transparent)]
pub struct RowCommitmentsEncoded(pub [G1Affine; BLOBN * 2]); // num_rows_encoded

impl Deref for RowCommitmentsEncoded {
    type Target = [G1Affine; BLOBN * 2];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RowCommitmentsEncoded {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct EncodedBlob {
    encoded: EncodedBlobEncoded,
    row_commitments_encoded: RowCommitmentsEncoded,
    row_coeff: [Scalar; BLOBN],
    da_commitment: G1Affine,
    row_merkle_roots: [H256; BLOBN],
    data_root: H256,
}

// pub struct  EncodedSlice {
//     slice: [H256; BLOBN],
//     row_coeff: [Scalar; BLOBN],
//     row_merkle_root: H256,
//     da_commitment: G1AffineCompressed,
//     merkle_proof: MerkleProof,
//     data_root: H256,
// }
