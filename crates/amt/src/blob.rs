use ark_poly::EvaluationDomain;
use ark_poly::Radix2EvaluationDomain;

use crate::proofs::AllProofs;
use crate::proofs::AmtProofError;
use crate::proofs::Proof;
use crate::utils::bitreverse;
use crate::utils::index_reverse;
use crate::{
    ec_algebra::{FftField, Field, Fr, Pairing, G1},
    utils::change_matrix_direction,
    AMTParams,
};

pub struct EncoderContext<PE: Pairing> {
    pub amt: AMTParams<PE>,
    pub coset_amt: AMTParams<PE>,
    log_n: usize,
}

impl<PE: Pairing> EncoderContext<PE> {
    pub fn new(dir: &str, expected_depth: usize, create_mode: bool) -> Self {
        let amt = AMTParams::from_dir(dir, expected_depth, create_mode, false);
        let coset_amt = AMTParams::from_dir(dir, expected_depth, create_mode, true);
        Self {
            amt,
            coset_amt,
            log_n: expected_depth,
        }
    }

    pub fn process_blob<const LOG_COL: usize, const LOG_ROW: usize>(
        &self,
        raw_blob: &[Fr<PE>],
    ) -> (
        HalfBlob<PE, LOG_COL, LOG_ROW>,
        HalfBlob<PE, LOG_COL, LOG_ROW>,
    ) {
        assert!(LOG_COL + LOG_ROW + 1 <= <Fr<PE> as FftField>::TWO_ADICITY as usize);
        assert_eq!(1 << (LOG_COL + LOG_ROW), raw_blob.len());
        assert_eq!(LOG_COL + LOG_ROW, self.log_n);

        let mut points = raw_blob.to_vec();
        change_matrix_direction(&mut points, LOG_COL, LOG_ROW);

        let coset_points = to_coset_blob::<PE>(&points);

        let primary_blob = HalfBlob::<PE, LOG_COL, LOG_ROW>::new(points, &self.amt);
        let coset_blob = HalfBlob::<PE, LOG_COL, LOG_ROW>::new(coset_points, &self.coset_amt);

        (primary_blob, coset_blob)
    }
}

fn to_coset_blob<PE: Pairing>(data: &[Fr<PE>]) -> Vec<Fr<PE>> {
    let fft_domain = Radix2EvaluationDomain::<Fr<PE>>::new(data.len()).unwrap();
    let coset = <Fr<PE> as FftField>::get_root_of_unity((data.len() * 2) as u64).unwrap();

    let mut coeff = fft_domain.ifft(data);
    coeff.iter_mut().enumerate().for_each(|(idx, x)| {
        *x *= &coset.pow(&[idx as u64]);
    });

    fft_domain.fft(&coeff)
}

pub struct HalfBlob<PE: Pairing, const LOG_COL: usize, const LOG_ROW: usize> {
    pub blob: Vec<Fr<PE>>,
    pub commitment: G1<PE>,
    pub proofs: AllProofs<PE>,
}

impl<PE: Pairing, const LOG_COL: usize, const LOG_ROW: usize> HalfBlob<PE, LOG_COL, LOG_ROW> {
    fn new(mut points: Vec<Fr<PE>>, amt: &AMTParams<PE>) -> Self {
        index_reverse(&mut points);
        let (commitment, proofs) = amt.gen_all_proofs(&points, 1 << LOG_COL);

        index_reverse(&mut points);
        change_matrix_direction(&mut points, LOG_ROW, LOG_COL);

        Self {
            blob: points,
            commitment,
            proofs,
        }
    }

    pub fn get_row(&self, index: usize) -> BlobRow<PE, LOG_COL, LOG_ROW> {
        assert!(index < 1 << LOG_ROW);

        let row_size = 1 << LOG_COL;
        let row = self.blob[row_size * index..row_size * (index + 1)].to_vec();

        let reversed_index = bitreverse(index, LOG_ROW);
        let proof = self.proofs.get_proof(reversed_index);

        BlobRow::<PE, LOG_COL, LOG_ROW> { row, proof, index }
    }
}

#[derive(Debug)]
pub struct BlobRow<PE: Pairing, const LOG_COL: usize, const LOG_ROW: usize> {
    pub index: usize,
    pub row: Vec<Fr<PE>>,
    pub proof: Proof<PE>,
}

impl<PE: Pairing, const LOG_COL: usize, const LOG_ROW: usize> BlobRow<PE, LOG_COL, LOG_ROW> {
    pub fn verify(&self, amt: &AMTParams<PE>, commitment: G1<PE>) -> Result<(), AmtProofError> {
        let mut data = self.row.clone();

        index_reverse(&mut data);
        let batch_index = bitreverse(self.index, LOG_ROW);
        amt.verify_proof(&data, batch_index, &self.proof, commitment)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_poly::Radix2EvaluationDomain;
    use once_cell::sync::Lazy;

    use crate::{
        ec_algebra::{Fr, UniformRand},
        utils::change_matrix_direction,
    };

    use super::EncoderContext;

    const LOG_ROW: usize = 3;
    const LOG_COL: usize = 5;
    type PE = Bn254;
    static ENCODER: Lazy<EncoderContext<PE>> =
        Lazy::new(|| EncoderContext::new("./pp", LOG_ROW + LOG_COL, true));

    fn random_scalars(length: usize) -> Vec<Fr<PE>> {
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| Fr::<PE>::rand(&mut rng))
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_encode_and_prove() {
        let scalars = random_scalars(1 << (LOG_ROW + LOG_COL));
        let (primary_blob, coset_blob) =
            ENCODER.process_blob::<LOG_COL, LOG_ROW>(scalars.as_slice());
        assert_eq!(primary_blob.blob, scalars);
        assert_eq!(primary_blob.commitment, coset_blob.commitment);

        for index in 0..(1 << LOG_ROW) {
            let commitment = primary_blob.commitment;
            let row = primary_blob.get_row(index);
            row.verify(&ENCODER.amt, commitment).unwrap();
        }

        for index in 0..(1 << LOG_ROW) {
            let commitment = coset_blob.commitment;
            let row = coset_blob.get_row(index);
            row.verify(&ENCODER.coset_amt, commitment).unwrap();
        }
    }

    #[test]
    fn test_erasure_encoding() {
        use ark_poly::EvaluationDomain;
        use ark_std::Zero;
        const LENGTH: usize = 1 << (LOG_ROW + LOG_COL);
        let scalars = random_scalars(LENGTH);
        let (primary_blob, coset_blob) =
            ENCODER.process_blob::<LOG_COL, LOG_ROW>(scalars.as_slice());
        assert_eq!(primary_blob.blob, scalars);

        let fft_domain = Radix2EvaluationDomain::<Fr<PE>>::new(LENGTH).unwrap();
        let fft2_domain = Radix2EvaluationDomain::<Fr<PE>>::new(LENGTH * 2).unwrap();

        let mut fft_input = scalars.clone();
        change_matrix_direction(&mut fft_input, LOG_COL, LOG_ROW);

        let mut coeff = fft_domain.ifft(&fft_input);
        coeff.extend(vec![Fr::<PE>::zero(); LENGTH]);

        let answer = fft2_domain.fft(&coeff[..]);
        let mut primary_half: Vec<Fr<PE>> = answer.iter().step_by(2).cloned().collect();
        let mut secondary_half: Vec<Fr<PE>> = answer.iter().skip(1).step_by(2).cloned().collect();

        change_matrix_direction(&mut primary_half, LOG_ROW, LOG_COL);
        change_matrix_direction(&mut secondary_half, LOG_ROW, LOG_COL);

        assert_eq!(primary_half, primary_blob.blob);
        assert_eq!(secondary_half, coset_blob.blob);
    }
}
