use binary_merkle_tree::MerkleProof;
use ethereum_types::H256;
use std::ops::{Deref, DerefMut};

use amt::BlobRow;
use amt::HalfBlob;
use ark_bn254::{Fr as Scalar, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand};

pub const RAW_UNIT: usize = 31;
pub const BLOB_UNIT: usize = 32;
pub const BLOB_ROW_LOG: usize = 6;
pub const BLOB_COL_LOG: usize = 7;
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
            Err(format!(
                "Input byte slice length {} exceeds the required length {} for RawData.",
                value.len(),
                RAW_UNIT * BLOB_ROW_N * BLOB_COL_N
            ))
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
pub struct EncodedBlobScalars(pub Vec<Scalar>); // BLOB_ROW_N2 * BLOB_COL_N

impl Deref for EncodedBlobScalars {
    type Target = Vec<Scalar>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for EncodedBlobScalars {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct EncodedBlobHalves<PE: Pairing, const BLOB_COL_LOG: usize, const BLOB_ROW_LOG: usize> {
    // BLOB_ROW_N2 * BLOB_COL_N
    pub primary: HalfBlob<PE, BLOB_COL_LOG, BLOB_ROW_LOG>,
    pub coset: HalfBlob<PE, BLOB_COL_LOG, BLOB_ROW_LOG>,
}

#[repr(transparent)]
pub struct EncodedBlobH256s(pub Vec<H256>); // BLOB_ROW_N2 * BLOB_COL_N

impl Deref for EncodedBlobH256s {
    type Target = Vec<H256>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for EncodedBlobH256s {
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

#[derive(Clone)]
pub struct SimulateSetup {
    pub setup_g1: Vec<G1Affine>,
    pub setup_g2: Vec<G2Affine>,
} // >= num_cols for each row's commitment

//pub const KZG_SETUP_N: usize = BLOB_ROW_N2; // std::cmp::max(BLOB_ROW_N2, BLOB_COL_N);
pub const KZG_SETUP_N_G2: usize = 1 << 1;
impl SimulateSetup {
    pub fn sim_load() -> Self {
        use ark_std::rand::thread_rng;
        let mut rng = thread_rng();
        let s: Scalar = Scalar::rand(&mut rng);
        //let s = <Scalar as Field>::from_random_bytes(&(3usize.to_le_bytes())).unwrap(); //
        let mut all_s: Vec<Scalar> = vec![s; std::cmp::max(BLOB_ROW_N2, BLOB_COL_N)];
        all_s[0] = Scalar::one();
        all_s = all_s
            .iter()
            .scan(Scalar::one(), |state, &x| {
                *state *= x;
                Some(*state)
            })
            .collect();
        //println!("{:?}", all_s); //
        let setup_g1: Vec<G1Affine> = all_s
            .iter()
            .map(|x| (G1Affine::generator() * x).into_affine())
            .collect();
        let setup_g2: Vec<G2Affine> = all_s[..KZG_SETUP_N_G2]
            .iter()
            .map(|x| (G2Affine::generator() * x).into_affine())
            .collect();
        Self { setup_g1, setup_g2 }
    }
}

pub struct EncodedBlobKZG {
    pub encoded: EncodedBlobScalars,
    pub row_commitments: RowCommitments,
    pub da_commitment: G1Affine,
    pub da_proofs: Vec<G1Affine>,
}

#[derive(Debug)]
pub struct EncodedSliceKZG {
    pub encoded: Vec<Scalar>, // BLOB_COL_N
    pub row_commitment: G1Affine,
    pub da_commitment: G1Affine,
    pub da_proof: G1Affine,
}

pub struct EncodedBlobMerkle {
    pub encoded: EncodedBlobH256s,
    pub row_merkle_roots: Vec<H256>, // BLOB_ROW_N
    pub data_root: H256,
}

#[derive(Debug)]
pub struct EncodedSliceMerkle {
    pub encoded: Vec<H256>,                    // BLOB_COL_N
    pub merkle_proof: MerkleProof<H256, H256>, // root, proof, number_of_leaves, leaf_index, leaf
}

#[derive(Debug)]
pub struct EncodedSliceHalves<PE: Pairing, const BLOB_COL_LOG: usize, const BLOB_ROW_LOG: usize> {
    pub commitment: G1Projective,
    pub row: BlobRow<PE, BLOB_COL_LOG, BLOB_ROW_LOG>, // index, row, proof
}

pub struct EncodedBlob {
    pub kzg: EncodedBlobKZG,
    pub merkle: EncodedBlobMerkle,
}

pub struct EncodedBlobAMT<PE: Pairing, const BLOB_COL_LOG: usize, const BLOB_ROW_LOG: usize> {
    pub amt: EncodedBlobHalves<PE, BLOB_COL_LOG, BLOB_ROW_LOG>,
    pub kzg: EncodedBlobKZG,
    pub merkle: EncodedBlobMerkle,
}

#[derive(Debug)]
pub struct EncodedSlice {
    pub index: usize,
    pub kzg: EncodedSliceKZG,
    pub merkle: EncodedSliceMerkle,
}

#[derive(Debug)]
pub struct EncodedSliceAMT<PE: Pairing, const BLOB_COL_LOG: usize, const BLOB_ROW_LOG: usize> {
    pub index: usize,
    pub amt: EncodedSliceHalves<PE, BLOB_COL_LOG, BLOB_ROW_LOG>,
    pub kzg: EncodedSliceKZG,
    pub merkle: EncodedSliceMerkle,
}
// pub struct  EncodedSlice {
//     slice: [H256; BLOBN],
//     row_coeff: [Scalar; BLOBN],
//     row_merkle_root: H256,
//     da_commitment: G1AffineCompressed,
//     merkle_proof: MerkleProof,
//     data_root: H256,
// }
