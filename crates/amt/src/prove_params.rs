#![allow(unused)]

use super::error;
use super::export::{
    k_adicity, AffineRepr, BigInteger, CanonicalDeserialize, CanonicalSerialize, CurveGroup,
    EvaluationDomain, FftField, Field, Fr, FrInt, G2Aff, Group, One, Pairing,
    Radix2EvaluationDomain, Zero, G1, G2,
};
use super::power_tau::PowerTau;
use super::utils::amtp_file_name;
use std::ops::Mul;

use rayon::prelude::*;

pub struct AMTParams<PE: Pairing> {
    idents: Vec<G1<PE>>,
    quotients: Vec<Vec<G1<PE>>>,
    verification: Vec<Vec<G2<PE>>>,
    g2: G2<PE>,
}

impl<PE: Pairing> AMTParams<PE> {
    pub fn get_commitments(&self, index: usize) -> &G1<PE> {
        &self.idents[index]
    }

    pub fn get_quotient(&self, depth: usize, index: usize) -> &G1<PE> {
        &self.quotients[depth - 1][index]
    }

    pub fn get_sibling_verification(&self, depth: usize, mut index: usize) -> &G2<PE> {
        index &= (1 << depth) - 1;
        index ^= 1 << (depth - 1);
        &self.verification[depth - 1][index]
    }

    pub fn g2(&self) -> G2<PE> {
        self.g2
    }

    pub fn get_idents_pow(&self, index: usize, power: &FrInt<PE>) -> G1<PE> {
        self.idents[index].mul_bigint(power)
    }

    pub fn get_quotient_pow(&self, depth: usize, index: usize, power: &FrInt<PE>) -> G1<PE> {
        self.quotients[depth - 1][index].mul_bigint(power)
    }

    fn load_cached(file: &str) -> Result<Self, error::Error> {
        let mut buffer = File::open(file)?;
        let commitments: Vec<G1<PE>> =
            CanonicalDeserialize::deserialize_uncompressed_unchecked(&mut buffer)?;
        let quotients: Vec<Vec<G1<PE>>> =
            CanonicalDeserialize::deserialize_uncompressed_unchecked(&mut buffer)?;
        let verification: Vec<Vec<G2<PE>>> =
            CanonicalDeserialize::deserialize_uncompressed_unchecked(&mut buffer)?;
        let length = commitments.len();
        let depth = k_adicity(2, length as u64) as usize;
        Ok(Self {
            idents: commitments,
            quotients,
            verification,
            g2: CanonicalDeserialize::deserialize_uncompressed_unchecked(&mut buffer)?,
        })
    }

    pub fn from_dir(dir: &str, expected_depth: usize, create_mode: bool) -> Self {
        let path = Path::new(dir).join(amtp_file_name::<PE>(expected_depth));
        let file = path.to_str().unwrap();
        match Self::load_cached(file) {
            Ok(params) => params,
            Err(_) => {
                let pp = if create_mode {
                    PowerTau::<PE>::from_dir_or_new(dir, expected_depth)
                } else {
                    PowerTau::<PE>::from_dir(dir, expected_depth)
                };

                let params = Self::from_pp(pp);
                let buffer = File::create(file).unwrap();

                params.idents.serialize_uncompressed(&buffer).unwrap();
                params.quotients.serialize_uncompressed(&buffer).unwrap();
                params.verification.serialize_uncompressed(&buffer).unwrap();
                params.g2.serialize_uncompressed(&buffer).unwrap();

                params
            }
        }
    }

    fn from_pp(pp: PowerTau<PE>) -> Self {
        let (g1pp, g2pp) = pp.into_projective();

        assert_eq!(g1pp.len(), g2pp.len());
        let length = g1pp.len();
        let depth = k_adicity(2, length as u64) as usize;

        let fft_domain = Radix2EvaluationDomain::<Fr<PE>>::new(length).unwrap();

        let commitments: Vec<G1<PE>> = fft_domain.ifft(&g1pp[..]);
        let quotients: Vec<Vec<G1<PE>>> = (1..=depth)
            .map(|d| Self::gen_quotients(&g1pp[..], &fft_domain, d))
            .collect();
        let verification: Vec<Vec<G2<PE>>> = (1..=depth)
            .map(|d| Self::gen_verify(&g2pp[..], d))
            .collect();

        Self {
            idents: commitments,
            quotients,
            verification,
            g2: g2pp[0],
        }
    }

    fn gen_idents(
        g1pp: &[G1<PE>],
        fft_domain: &Radix2EvaluationDomain<Fr<PE>>,
    ) -> Vec<G1<PE>> {
        fft_domain.ifft(&g1pp)
    }

    fn gen_quotients(
        g1pp: &[G1<PE>],
        fft_domain: &Radix2EvaluationDomain<Fr<PE>>,
        depth: usize,
    ) -> Vec<G1<PE>> {
        println!("gen_quotients level {}", depth);
        assert!(g1pp.len() <= 1 << 32);

        let length = g1pp.len();
        let max_depth = k_adicity(2, length as u64) as usize;

        assert_eq!(1 << max_depth, length);
        assert!(max_depth >= depth);
        assert!(depth >= 1);

        let mut coeff = vec![G1::<PE>::zero(); length];
        let max_coeff = 1usize << (max_depth - depth);
        for i in 1..=max_coeff {
            coeff[i] = g1pp[max_coeff - i];
        }

        let mut answer = fft_domain.fft(&coeff);
        answer
            .par_iter_mut()
            .with_min_len(1024)
            .for_each(|val| *val *= fft_domain.size_inv);
        answer
    }

    fn gen_verify(g2pp: &[G2<PE>], depth: usize) -> Vec<G2<PE>> {
        println!("gen_proof level {}", depth);
        assert!(g2pp.len() <= 1 << 32);

        let length = g2pp.len();
        let max_depth = k_adicity(2, length as u64) as usize;

        assert_eq!(1 << max_depth, length);
        assert!(max_depth >= depth);
        assert!(depth >= 1);

        let height = max_depth - depth;
        let step = 1 << height;
        let mut fft_domain = Radix2EvaluationDomain::<Fr<PE>>::new(1 << depth).unwrap();
        let (w, w_inv) = (fft_domain.group_gen, fft_domain.group_gen_inv);
        fft_domain.group_gen = w_inv;
        fft_domain.group_gen_inv = w;
        let mut coeff = vec![G2::<PE>::zero(); 1 << depth];

        coeff[0] = g2pp[length - step];
        for i in 1..length / step {
            coeff[i] = g2pp[(i - 1) * step]
        }
        fft_domain.fft(&coeff)
    }
}

#[test]
fn test_ident_prove() {
    const TEST_LEVEL: usize = 6;
    const TEST_LENGTH: usize = 1 << TEST_LEVEL;
    type Pairing = ark_bn254::Bn254;
    type TestParams = AMTParams<Pairing>;

    let (g1pp, g2pp) = PowerTau::<Pairing>::from_dir_or_new("./pp", TEST_LEVEL).into_projective();
    let g1 = g1pp[0];
    let g2 = g2pp[0];
    let w = Fr::<Pairing>::get_root_of_unity(TEST_LENGTH as u64).unwrap();
    let len = TEST_LENGTH;
    assert_eq!(w.pow(&[TEST_LENGTH as u64]), Fr::<Pairing>::one());

    let fft_domain = Radix2EvaluationDomain::new(TEST_LENGTH).unwrap();

    // Test bottom level
    let indents = TestParams::gen_idents(&g1pp[..], &fft_domain);
    let prove_data = TestParams::gen_quotients(&g1pp[..], &fft_domain, TEST_LEVEL);
    let verify_data = TestParams::gen_verify(&g2pp[..], TEST_LEVEL);

    for t in 0..TEST_LENGTH {
        let mut answer: G1<Pairing> = g1pp
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, mut val)| {
                val *= fft_domain.group_gen_inv.pow([(t * idx) as u64]);
                val
            })
            .sum();
        answer *= fft_domain.size_inv;
        assert_eq!(indents[t], answer);
    }

    for t in 0..TEST_LENGTH {
        let answer: G2<Pairing> = g2pp
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, mut val)| {
                val *= fft_domain.group_gen.pow([(t * (len - 1 - idx)) as u64]);
                val
            })
            .sum();
        assert_eq!(verify_data[t], answer);
    }

    for t in 0..TEST_LENGTH {
        let mut answer: G1<Pairing> = g1;
        answer *= fft_domain.group_gen.pow([t as u64]);
        answer *= fft_domain.size_inv;
        assert_eq!(prove_data[t], answer);
    }

    for t in 0..TEST_LENGTH {
        assert_eq!(
            Pairing::pairing(indents[t], g2),
            Pairing::pairing(prove_data[t], verify_data[t])
        );
    }

    for depth in (1..TEST_LEVEL).rev() {
        dbg!(depth);
        let prove_data = TestParams::gen_quotients(&g1pp[..], &fft_domain, depth);
        let verify_data = TestParams::gen_verify(&g2pp[..], depth);
        for t in 0..TEST_LENGTH {
            dbg!(t);
            assert_eq!(
                Pairing::pairing(indents[t], g2),
                Pairing::pairing(prove_data[t], verify_data[t % (1 << depth)])
            );
        }
    }
}

#[inline]
fn bitreverse(mut n: usize, l: usize) -> usize {
    let mut r = 0;
    for _ in 0..l {
        r = (r << 1) | (n & 1);
        n >>= 1;
    }
    r
}

use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::sync::RwLock;
