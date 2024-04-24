use crate::ec_algebra::{Fr, G1Aff, G2Aff, Pairing, G1, G2};
use crate::proofs::{AmtProofError, Proof};

use ark_ec::VariableBaseMSM;

use super::AMTParams;

impl<PE: Pairing> AMTParams<PE>
where
    G1<PE>: VariableBaseMSM<MulBase = G1Aff<PE>>,
{
    pub fn verify_proof(
        &self,
        ri_data: &[Fr<PE>],
        batch_index: usize,
        proof: &Proof<PE>,
        commitment: G1<PE>,
    ) -> Result<(), AmtProofError> {
        verify_amt_proof(
            &self.basis,
            &self.vanishes,
            ri_data,
            batch_index,
            proof,
            commitment,
            &self.g2,
        )
    }
}

pub fn verify_amt_proof<PE: Pairing>(
    basis: &[G1Aff<PE>],
    vanishes: &[Vec<G2Aff<PE>>],
    ri_data: &[Fr<PE>],
    batch_index: usize,
    proof: &Proof<PE>,
    commitment: G1<PE>,
    g2: &G2<PE>,
) -> Result<(), AmtProofError>
where
    G1<PE>: VariableBaseMSM<MulBase = G1Aff<PE>>,
{
    use AmtProofError::*;

    let proof_depth = proof.len();
    let num_batch = 1 << proof_depth;
    let batch = basis.len() / num_batch;

    if batch != ri_data.len() {
        return Err(UnexpectedDataLength);
    }
    if batch_index >= num_batch {
        return Err(IncorrectPosition);
    }
    assert!(batch_index < num_batch);

    let self_commitment: G1<PE> = VariableBaseMSM::msm(
        &basis[batch_index * batch..(batch_index + 1) * batch],
        ri_data,
    )
    .unwrap();

    let mut overall_commitment = self_commitment;
    for (d, (commitment, quotient)) in proof.iter().enumerate().rev() {
        let vanish_index = batch_index >> (proof_depth - 1 - d);
        let vanish = vanishes[d][vanish_index ^ 1];
        if PE::pairing(commitment, g2) != PE::pairing(quotient, vanish) {
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
