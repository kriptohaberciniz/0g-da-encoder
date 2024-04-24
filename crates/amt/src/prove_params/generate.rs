use std::fs::File;
use std::path::Path;

use crate::ec_algebra::{
    k_adicity, CanonicalDeserialize, CanonicalSerialize, EvaluationDomain, Field, Fr, G1Aff, G2Aff,
    One, Pairing, Radix2EvaluationDomain, Zero, G1, G2,
};
use crate::error;
use crate::power_tau::PowerTau;
use crate::utils::{amtp_file_name, index_reverse};

use super::AMTParams;

use ark_ec::CurveGroup;
use ark_ff::FftField;
use rayon::prelude::*;

impl<PE: Pairing> AMTParams<PE> {
    pub fn from_dir(dir: &str, expected_depth: usize, create_mode: bool, coset: bool) -> Self {
        let path = Path::new(dir).join(amtp_file_name::<PE>(expected_depth, coset, false));
        let file = path.to_str().unwrap();

        if let Ok(params) = Self::load_cached(file) {
            return params;
        }

        if !create_mode {
            panic!("Fail to load amt params from {}", file);
        }

        let pp = PowerTau::<PE>::from_dir(dir, expected_depth, create_mode);

        let params = Self::from_pp(pp, coset);
        let buffer = File::create(file).unwrap();

        params.serialize_uncompressed(&buffer).unwrap();

        params
    }

    fn load_cached(file: &str) -> Result<Self, error::Error> {
        let mut buffer = File::open(file)?;
        Ok(CanonicalDeserialize::deserialize_uncompressed_unchecked(
            &mut buffer,
        )?)
    }

    pub fn len(&self) -> usize {
        self.basis.len()
    }

    fn enact<T: CurveGroup>(input: Vec<T>) -> Vec<<T as CurveGroup>::Affine> {
        let mut affine = CurveGroup::normalize_batch(input.as_slice());
        index_reverse(&mut affine);
        affine
    }

    pub fn from_pp(pp: PowerTau<PE>, coset: bool) -> Self {
        println!("Generate AMT Params");
        let (mut g1pp, mut g2pp) = pp.into_projective();

        assert_eq!(g1pp.len(), g2pp.len());
        assert!(g1pp.len().is_power_of_two());
        let length = g1pp.len();
        let depth = ark_std::log2(length) as usize;

        if coset {
            println!("Make coset");
            let w = Fr::<PE>::one()
                / <Fr<PE> as FftField>::get_root_of_unity(length as u64 * 2).unwrap();
            g1pp.par_iter_mut()
                .enumerate()
                .for_each(|(idx, x)| *x *= w.pow(&[idx as u64]));
            g2pp.par_iter_mut()
                .enumerate()
                .for_each(|(idx, x)| *x *= w.pow(&[idx as u64]));
        }

        let fft_domain = Radix2EvaluationDomain::<Fr<PE>>::new(length).unwrap();

        let basis: Vec<G1Aff<PE>> = Self::enact(Self::gen_basis(&g1pp[..], &fft_domain));
        let quotients: Vec<Vec<G1Aff<PE>>> = (1..=depth)
            .map(|d| Self::enact(Self::gen_quotients(&g1pp[..], &fft_domain, d)))
            .collect();
        let vanishes: Vec<Vec<G2Aff<PE>>> = (1..=depth)
            .map(|d| Self::enact(Self::gen_vanishes(&g2pp[..], d)))
            .collect();

        Self {
            basis,
            quotients,
            vanishes,
            g2: g2pp[0],
        }
    }

    fn gen_basis(g1pp: &[G1<PE>], fft_domain: &Radix2EvaluationDomain<Fr<PE>>) -> Vec<G1<PE>> {
        println!("Generate basis level");
        fft_domain.ifft(&g1pp)
    }

    fn gen_quotients(
        g1pp: &[G1<PE>],
        fft_domain: &Radix2EvaluationDomain<Fr<PE>>,
        depth: usize,
    ) -> Vec<G1<PE>> {
        println!("Generate quotients level {}", depth);
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

    fn gen_vanishes(g2pp: &[G2<PE>], depth: usize) -> Vec<G2<PE>> {
        println!("Generate vanishes level {}", depth);
        assert!(g2pp.len() <= 1 << 32);

        let length = g2pp.len();
        let max_depth = k_adicity(2, length as u64) as usize;

        assert_eq!(1 << max_depth, length);
        assert!(max_depth >= depth);
        assert!(depth >= 1);

        let height = max_depth - depth;
        let step = 1 << height;
        let mut fft_domain = Radix2EvaluationDomain::<Fr<PE>>::new(1 << depth).unwrap();

        let mut coeff = vec![G2::<PE>::zero(); 1 << depth];

        coeff[0] = g2pp[length - step];
        for i in 1..length / step {
            coeff[i] = g2pp[(i - 1) * step]
        }

        std::mem::swap(&mut fft_domain.group_gen, &mut fft_domain.group_gen_inv);
        fft_domain.fft(&coeff)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{TestParams, DOMAIN, G1PP, G2PP, PE, PP, TEST_LENGTH, TEST_LEVEL, W};
    use crate::ec_algebra::{
        EvaluationDomain, Field, Fr, One, Pairing, VariableBaseMSM, Zero, G1, G2,
    };

    fn simple_gen_basis(index: usize) -> G1<PE> {
        let mut points = vec![Fr::<PE>::zero(); TEST_LENGTH];
        points[index] = Fr::<PE>::one();

        let coeff = DOMAIN.ifft(&points);
        G1::<PE>::msm(&PP.0, &coeff[..]).unwrap()
    }

    #[test]
    fn test_gen_basis() {
        let indents = TestParams::gen_basis(&G1PP, &*DOMAIN);
        for t in 0..TEST_LENGTH {
            assert_eq!(indents[t], simple_gen_basis(t))
        }
    }

    fn simple_gen_quotinents(index: usize, depth: usize) -> G1<PE> {
        let size = TEST_LENGTH / (1 << depth);
        (0..size)
            .rev()
            .map(|j| W.pow(&[(index * j) as u64]))
            .zip(PP.0[0..size].iter())
            .map(|(exp, base)| *base * exp)
            .sum::<G1<PE>>()
            * DOMAIN.size_inv
            * W.pow(&[index as u64])
    }

    #[test]
    fn test_gen_quotients() {
        for depth in (1..=TEST_LEVEL).rev() {
            let quotients = TestParams::gen_quotients(&G1PP, &DOMAIN, depth);
            for t in 0..TEST_LENGTH {
                assert_eq!(quotients[t], simple_gen_quotinents(t, depth));
            }
        }
    }

    fn simple_gen_vanishes(index: usize, depth: usize) -> G2<PE> {
        let step = TEST_LENGTH / (1 << depth);
        let size = 1 << depth;
        (0..size)
            .rev()
            .map(|j| W.pow(&[(index * step * j) as u64]))
            .zip(PP.1.iter().step_by(step))
            .map(|(exp, base)| *base * exp)
            .sum()
    }

    #[test]
    fn test_gen_vanishes() {
        for depth in (1..=TEST_LEVEL).rev() {
            let vanishes = TestParams::gen_vanishes(&G2PP, depth);
            for t in 0..TEST_LENGTH {
                assert_eq!(vanishes[t % (1 << depth)], simple_gen_vanishes(t, depth));
            }
        }
    }

    #[test]
    fn test_simple_gen_params() {
        for depth in (1..=TEST_LEVEL).rev() {
            for t in 0..TEST_LENGTH {
                assert_eq!(
                    PE::pairing(simple_gen_basis(t), G2PP[0]),
                    PE::pairing(
                        simple_gen_quotinents(t, depth),
                        simple_gen_vanishes(t, depth)
                    )
                );
            }
        }
    }

    #[test]
    fn test_gen_params() {
        let basis = TestParams::gen_basis(&G1PP, &DOMAIN);
        for depth in (1..=TEST_LEVEL).rev() {
            let prove_data = TestParams::gen_quotients(&G1PP, &DOMAIN, depth);
            let verify_data = TestParams::gen_vanishes(&G2PP, depth);
            for t in 0..TEST_LENGTH {
                assert_eq!(
                    PE::pairing(basis[t], G2PP[0]),
                    PE::pairing(prove_data[t], verify_data[t % (1 << depth)])
                );
            }
        }
    }
}
