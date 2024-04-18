// Re-export all the required components in Arkworks's repo (original Zexe).

// Since Zexe's repo doesn't have a stable implementation and could be refactored in the future,
// we import all the required objects in one place and all its usage for this repo should import from here.

pub use ark_ec::pairing::Pairing;
pub use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
pub use ark_ff::{
    utils::k_adicity, BigInteger, FftField, Field, One, PrimeField, UniformRand, Zero,
};
pub use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
pub use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
};

pub type G1<PE> = <PE as Pairing>::G1;
pub type G1Aff<PE> = <PE as Pairing>::G1Affine;
pub type G2<PE> = <PE as Pairing>::G2;
pub type G2Aff<PE> = <PE as Pairing>::G2Affine;
pub type Fr<PE> = <PE as Pairing>::ScalarField;
pub type FrInt<PE> = <Fr<PE> as PrimeField>::BigInt;
