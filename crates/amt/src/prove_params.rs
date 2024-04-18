use crate::ec_algebra::{
    k_adicity, AffineRepr, CanonicalDeserialize, CanonicalSerialize, EvaluationDomain, Field, Fr,
    G1Aff, G2Aff, One, Pairing, Radix2EvaluationDomain, Zero, G1, G2,
};
use crate::error;
use crate::power_tau::PowerTau;
use crate::proofs::{AllProofs, AmtProofError, Proof};
use crate::utils::{amtp_file_name, index_reverse};

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::FftField;
use rayon::prelude::*;

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct AMTParams<PE: Pairing> {
    pub basis: Vec<G1Aff<PE>>,
    pub quotients: Vec<Vec<G1Aff<PE>>>,
    pub vanishes: Vec<Vec<G2Aff<PE>>>,
    pub g2: G2<PE>,
}

impl<PE: Pairing> AMTParams<PE> {
    pub fn from_dir(dir: &str, expected_depth: usize, create_mode: bool, coset: bool) -> Self {
        let path = Path::new(dir).join(amtp_file_name::<PE>(expected_depth, coset));
        let file = path.to_str().unwrap();

        if let Ok(params) = Self::load_cached(file) {
            return params;
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
        let (mut g1pp, mut g2pp) = pp.into_projective();

        assert_eq!(g1pp.len(), g2pp.len());
        assert!(g1pp.len().is_power_of_two());
        let length = g1pp.len();
        let depth = ark_std::log2(length) as usize;

        if coset {
            let w = Fr::<PE>::one()
                / <Fr<PE> as FftField>::get_root_of_unity(length as u64 * 2).unwrap();
            g1pp.iter_mut()
                .enumerate()
                .for_each(|(idx, x)| *x *= w.pow(&[idx as u64]));
            g2pp.iter_mut()
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

    fn gen_vanishes(g2pp: &[G2<PE>], depth: usize) -> Vec<G2<PE>> {
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

        let mut coeff = vec![G2::<PE>::zero(); 1 << depth];

        coeff[0] = g2pp[length - step];
        for i in 1..length / step {
            coeff[i] = g2pp[(i - 1) * step]
        }

        std::mem::swap(&mut fft_domain.group_gen, &mut fft_domain.group_gen_inv);
        fft_domain.fft(&coeff)
    }
}

impl<PE: Pairing> AMTParams<PE>
where
    G1<PE>: VariableBaseMSM<MulBase = G1Aff<PE>>,
{
    #[allow(unused)]
    pub(crate) fn commitment(&self, ri_data: &[Fr<PE>]) -> G1<PE> {
        VariableBaseMSM::msm(self.basis.as_slice(), ri_data).unwrap()
    }

    pub fn gen_commitment_tree(
        &self,
        ri_data: &[Fr<PE>],
        batch_size: usize,
    ) -> (G1Aff<PE>, Vec<Vec<G1Aff<PE>>>) {
        assert!(batch_size.is_power_of_two());
        assert!(batch_size <= self.len());

        let scalars = ri_data.chunks_exact(batch_size);
        let last_layer = self
            .basis
            .chunks_exact(batch_size)
            .zip(scalars)
            .map(|(base, scalar)| VariableBaseMSM::msm(base, scalar).unwrap())
            .collect::<Vec<G1<PE>>>();

        let mut answer = VecDeque::new();
        let mut last_layer = CurveGroup::normalize_batch(&last_layer);
        while last_layer.len() > 1 {
            let next_layer = last_layer
                .chunks_exact(2)
                .map(|x| x[0] + x[1])
                .collect::<Vec<_>>();
            let mut to_push_layer = CurveGroup::normalize_batch(&next_layer);
            std::mem::swap(&mut last_layer, &mut to_push_layer);
            answer.push_front(to_push_layer);
        }
        (last_layer[0], answer.into())
    }

    pub fn gen_prove_tree(&self, ri_data: &[Fr<PE>], batch_size: usize) -> Vec<Vec<G1Aff<PE>>> {
        assert!(batch_size.is_power_of_two());
        assert!(batch_size < self.len());
        assert_eq!(ri_data.len(), self.len());

        let last_depth = ark_std::log2(self.len() / batch_size) as usize;

        let mut answer = vec![];
        for depth in 1..=last_depth {
            let items = 1 << depth;
            let chunk_size = self.len() / items;
            let scalars = ri_data.chunks_exact(chunk_size);

            let quotients = self.quotients[depth - 1]
                .chunks_exact(chunk_size)
                .zip(scalars)
                .map(|(base, scalar)| VariableBaseMSM::msm(base, scalar).unwrap())
                .collect::<Vec<G1<PE>>>();
            answer.push(CurveGroup::normalize_batch(quotients.as_slice()))
        }
        answer
    }

    pub fn gen_all_proofs(&self, ri_data: &[Fr<PE>], batch_size: usize) -> (G1<PE>, AllProofs<PE>) {
        let proofs = self.gen_prove_tree(ri_data, batch_size);
        let (commitment, commitments) = self.gen_commitment_tree(ri_data, batch_size);
        let all_proofs = AllProofs {
            commitments,
            proofs,
            input_len: self.len(),
            batch_size,
        };
        (commitment.into_group(), all_proofs)
    }

    pub fn verify_proof(
        &self,
        ri_data: &[Fr<PE>],
        batch_index: usize,
        proof: &Proof<PE>,
        commitment: G1<PE>,
    ) -> Result<(), AmtProofError> {
        use AmtProofError::*;

        let proof_depth = proof.len();
        let num_batch = 1 << proof_depth;
        let batch = self.len() / num_batch;

        if batch != ri_data.len() {
            return Err(UnexpectedDataLength);
        }
        if batch_index >= num_batch {
            return Err(IncorrectPosition);
        }
        assert!(batch_index < num_batch);

        let self_commitment: G1<PE> = VariableBaseMSM::msm(
            &self.basis[batch_index * batch..(batch_index + 1) * batch],
            ri_data,
        )
        .unwrap();

        let mut overall_commitment = self_commitment;
        for (d, (commitment, quotient)) in proof.iter().enumerate().rev() {
            let vanish_index = batch_index >> (proof_depth - 1 - d);
            let vanish = self.vanishes[d][vanish_index ^ 1];
            if PE::pairing(commitment, self.g2) != PE::pairing(quotient, vanish) {
                return Err(KzgError(d));
            }
            overall_commitment += commitment;
        }
        if overall_commitment != commitment {
            Err(InconsistentCommitment)
        } else {
            Ok(())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec_algebra::{Field, One, UniformRand, VariableBaseMSM};
    use ark_ec::AffineRepr;
    use once_cell::sync::Lazy;

    const TEST_LEVEL: usize = 8;
    const TEST_LENGTH: usize = 1 << TEST_LEVEL;
    type PE = ark_bn254::Bn254;
    type TestParams = AMTParams<PE>;

    static PP: Lazy<PowerTau<PE>> =
        Lazy::new(|| PowerTau::<PE>::from_dir("./pp", TEST_LEVEL, true));

    static AMT: Lazy<AMTParams<PE>> = Lazy::new(|| AMTParams::from_pp(PP.clone(), false));

    static G1PP: Lazy<Vec<G1<PE>>> =
        Lazy::new(|| PP.0.iter().copied().map(|x| G1::<PE>::from(x)).collect());

    static G2PP: Lazy<Vec<G2<PE>>> =
        Lazy::new(|| PP.1.iter().copied().map(|x| G2::<PE>::from(x)).collect());

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fr<PE>>> =
        Lazy::new(|| Radix2EvaluationDomain::new(TEST_LENGTH).unwrap());

    static W: Lazy<Fr<PE>> = Lazy::new(|| DOMAIN.group_gen);

    fn random_scalars(length: usize) -> Vec<Fr<PE>> {
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| Fr::<PE>::rand(&mut rng))
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_coset_consistency() {
        let input = random_scalars(TEST_LENGTH);

        let fft_domain = Radix2EvaluationDomain::<Fr<PE>>::new(TEST_LENGTH).unwrap();
        let fft2_domain = Radix2EvaluationDomain::<Fr<PE>>::new(TEST_LENGTH * 2).unwrap();

        let mut coeff = fft_domain.ifft(&input);
        let mut coset_coeff = coeff.clone();
        coeff.extend(vec![Fr::<PE>::zero(); TEST_LENGTH]);

        let answer = fft2_domain.fft(&coeff[..]);

        for i in 0..TEST_LENGTH {
            assert_eq!(answer[i * 2], input[i]);
        }

        coset_coeff.iter_mut().enumerate().for_each(|(idx, x)| {
            *x *= &fft2_domain.group_gen.pow(&[idx as u64]);
        });
        let coset = fft_domain.fft(&coset_coeff);
        for i in 0..TEST_LENGTH {
            assert_eq!(answer[i * 2 + 1], coset[i]);
        }
    }

    fn simple_gen_basis(index: usize) -> G1<PE> {
        let mut points = vec![Fr::<PE>::zero(); TEST_LENGTH];
        points[index] = Fr::<PE>::one();

        let coeff = DOMAIN.ifft(&points);
        G1::<PE>::msm(&PP.0, &coeff[..]).unwrap()
    }

    #[test]
    fn test_gen_basis() {
        let indents = TestParams::gen_basis(&G1PP, &DOMAIN);
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

    #[test]
    fn test_commitment_tree() {
        let ri_data = &random_scalars(TEST_LENGTH);
        for log_batch in 0..=TEST_LEVEL {
            assert_eq!(
                AMT.commitment(ri_data),
                AMT.gen_commitment_tree(ri_data, 1 << log_batch)
                    .0
                    .into_group()
            )
        }
    }

    fn check_proof_tree(ri_data: &[Fr<PE>], batch: usize) {
        let (_, commitments) = AMT.gen_commitment_tree(ri_data, batch);
        let proofs = AMT.gen_prove_tree(ri_data, batch);
        for d in 0..(TEST_LEVEL - ark_std::log2(batch) as usize) {
            assert_eq!(commitments[d].len(), 1 << (d + 1));
            assert_eq!(proofs[d].len(), 1 << (d + 1));
            assert_eq!(AMT.vanishes[d].len(), 1 << (d + 1));
            for i in 0..1usize << (d + 1) {
                assert_eq!(
                    PE::pairing(commitments[d][i], G2PP[0]),
                    PE::pairing(proofs[d][i], AMT.vanishes[d][i])
                );
            }
        }
    }

    #[test]
    fn test_proof_tree() {
        let ri_data = &random_scalars(TEST_LENGTH);
        for d in 1..TEST_LEVEL {
            check_proof_tree(ri_data.as_slice(), 1 << d);
        }
    }

    #[test]
    fn test_proof_verify() {
        let ri_data = random_scalars(TEST_LENGTH);
        let commitment = AMT.commitment(&ri_data);

        for log_batch in 0..TEST_LEVEL {
            let batch = 1 << log_batch;
            let all_proofs = AMT.gen_all_proofs(&ri_data, batch).1;
            for (index, data) in ri_data.chunks_exact(batch).enumerate() {
                let proof = all_proofs.get_proof(index);
                AMT.verify_proof(&data, index, &proof, commitment).unwrap();
            }
        }
    }
}

use std::collections::VecDeque;
use std::fs::File;
use std::path::Path;
