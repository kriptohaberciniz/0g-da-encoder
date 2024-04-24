// use crate::ark::FqRepr;
use std::marker::PhantomData;

pub use ark_ff::{One as _, PrimeField as _, Zero as _};
pub use ark_std::str::FromStr;
pub use bellman_ce::pairing::CurveAffine as _;
pub use ff::{Field as _, PrimeField as _};
use std::fmt::{Debug, Display};

mod ppot {
    pub use bellman_ce::pairing::bn256::Bn256 as Bn;
    pub use bellman_ce::pairing::bn256::{Fq, Fq2, FqRepr, Fr, FrRepr, G1Affine, G2Affine, G1, G2};
}

mod ark {
    pub use ark_ff::{fields::PrimeField, Field, One};

    pub use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
    pub use ark_ff::biginteger::BigInteger256 as FqRepr;
    pub use ark_ff::biginteger::BigInteger256 as FrRepr;

    pub use ark_bn254::{FqParameters, FrParameters};
    pub use ark_ff::fields::Fp256;
}

pub trait Adapter {
    type Output: Debug + PartialEq + Sized + Eq + Copy + Clone + Send + Sync + Display;
    fn adapt(self) -> Self::Output;
}

impl Adapter for ppot::FqRepr {
    type Output = ark::FqRepr;

    fn adapt(self) -> Self::Output {
        ark::FqRepr(self.0)
    }
}

impl Adapter for ppot::FrRepr {
    type Output = ark::FrRepr;

    fn adapt(self) -> Self::Output {
        ark::FrRepr(self.0)
    }
}

impl Adapter for ppot::Fq {
    type Output = ark::Fq;

    fn adapt(self) -> Self::Output {
        ark::Fp256::<ark::FqParameters>(self.into_raw_repr().adapt(), PhantomData)
    }
}

impl Adapter for ppot::Fr {
    type Output = ark::Fr;

    fn adapt(self) -> Self::Output {
        ark::Fp256::<ark::FrParameters>(self.into_raw_repr().adapt(), PhantomData)
    }
}

impl Adapter for ppot::Fq2 {
    type Output = ark::Fq2;

    fn adapt(self) -> Self::Output {
        ark::Fq2::new(self.c0.adapt(), self.c1.adapt())
    }
}

impl Adapter for ppot::G1Affine {
    type Output = ark::G1Affine;

    fn adapt(self) -> Self::Output {
        if self.is_zero() {
            ark::G1Affine::zero()
        } else {
            ark::G1Affine::new(self.get_x().adapt(), self.get_y().clone().adapt(), false)
        }
    }
}

impl Adapter for ppot::G2Affine {
    type Output = ark::G2Affine;

    fn adapt(self) -> Self::Output {
        if self.is_zero() {
            ark::G2Affine::zero()
        } else {
            ark::G2Affine::new(self.get_x().adapt(), self.get_y().clone().adapt(), false)
        }
    }
}