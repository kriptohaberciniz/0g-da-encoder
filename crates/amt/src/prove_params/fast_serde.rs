use crate::ec_algebra::{
    BigInt, BigInteger, CanonicalDeserialize, CanonicalSerialize, Fq, Fq2, G1Aff, G2Aff,
    PrimeField, Read, Write, G2,
};
use crate::error::Result;
use crate::AMTParams;

use ark_bn254::Bn254;
use rayon::prelude::*;
use std::marker::PhantomData;

const HEADER: [u8; 4] = *b"bamt";
type PE = Bn254;

pub fn write<W: Write>(params: &AMTParams<PE>, mut writer: W) -> Result<()> {
    writer.write(&HEADER)?;

    let degree = ark_std::log2(params.basis.len()) as u8;
    degree.serialize_uncompressed(&mut writer)?;

    params.g2.serialize_uncompressed(&mut writer)?;

    for b in &params.basis {
        if b.infinity {
            return Err("Unsafe params with zero point".into());
        }

        b.x.0.serialize_uncompressed(&mut writer)?;
        b.y.0.serialize_uncompressed(&mut writer)?;
    }

    for layer in &params.quotients {
        for b in layer {
            if b.infinity {
                return Err("Unsafe params with zero point".into());
            }

            b.x.0.serialize_uncompressed(&mut writer)?;
            b.y.0.serialize_uncompressed(&mut writer)?;
        }
    }

    for layer in &params.vanishes {
        for b in layer {
            if b.infinity {
                return Err("Unsafe params with zero point".into());
            }

            b.x.c0.0.serialize_uncompressed(&mut writer)?;
            b.x.c1.0.serialize_uncompressed(&mut writer)?;
            b.y.c0.0.serialize_uncompressed(&mut writer)?;
            b.y.c1.0.serialize_uncompressed(&mut writer)?;
        }
    }
    Ok(())
}

pub fn read<R: Read>(mut reader: R) -> Result<AMTParams<PE>> {
    let header = <[u8; 4]>::deserialize_uncompressed_unchecked(&mut reader)?;
    if header != HEADER {
        return Err("Incorrect format".into());
    }

    let degree = u8::deserialize_uncompressed_unchecked(&mut reader)? as usize;
    let g2 = G2::<PE>::deserialize_uncompressed(&mut reader)?;

    let basis = read_amt_g1_line(&mut reader, 1 << degree)?;

    let mut quotients = vec![];
    for _ in 0..degree {
        quotients.push(read_amt_g1_line(&mut reader, 1 << degree)?);
    }

    let mut vanishes = vec![];
    for d in 0..degree {
        vanishes.push(read_amt_g2_line(&mut reader, 1 << (d + 1))?);
    }

    Ok(AMTParams {
        basis,
        quotients,
        vanishes,
        g2,
    })
}

const BASE_SIZE: usize = <<Fq<PE> as PrimeField>::BigInt as BigInteger>::NUM_LIMBS;
const BASE_BYTES: usize = BASE_SIZE * 8;
fn read_amt_g1_line<R: Read>(mut reader: R, length: usize) -> Result<Vec<G1Aff<PE>>> {
    let mut buffer = vec![0u8; BASE_BYTES * length * 2];
    reader.read_exact(&mut buffer)?;
    buffer
        .par_chunks_mut(BASE_BYTES * 2)
        .map(|raw| -> Result<_> {
            let x = read_mont_base(&raw[0..BASE_BYTES])?;
            let y = read_mont_base(&raw[BASE_BYTES..BASE_BYTES * 2])?;
            Ok(if cfg!(test) {
                G1Aff::<PE>::new(x, y)
            } else {
                G1Aff::<PE>::new_unchecked(x, y)
            })
        })
        .collect::<Result<Vec<_>>>()
}

pub fn read_mont_base(raw: &[u8]) -> Result<Fq<PE>> {
    Ok(ark_ff::Fp(
        BigInt::<BASE_SIZE>::deserialize_uncompressed_unchecked(raw)?,
        PhantomData,
    ))
}

fn read_amt_g2_line<R: Read>(mut reader: R, length: usize) -> Result<Vec<G2Aff<PE>>> {
    let mut buffer = vec![0u8; BASE_BYTES * length * 4];
    reader.read_exact(&mut buffer)?;
    buffer
        .par_chunks_mut(BASE_BYTES * 4)
        .map(|raw| -> Result<_> {
            let x0 = read_mont_base(&raw[0..BASE_BYTES])?;
            let x1 = read_mont_base(&raw[BASE_BYTES..BASE_BYTES * 2])?;
            let y0 = read_mont_base(&raw[BASE_BYTES * 2..BASE_BYTES * 3])?;
            let y1 = read_mont_base(&raw[BASE_BYTES * 3..])?;

            let x = Fq2::<PE>::new(x0, x1);
            let y = Fq2::<PE>::new(y0, y1);
            Ok(if cfg!(test) {
                G2Aff::<PE>::new(x, y)
            } else {
                G2Aff::<PE>::new_unchecked(x, y)
            })
        })
        .collect::<Result<Vec<_>>>()
}

#[cfg(test)]
mod tests {
    use super::super::tests::AMT;
    use super::{read, write};

    #[test]
    fn test_fast_serde() {
        let mut buffer = Vec::new();
        let writer: &mut Vec<u8> = &mut buffer;
        write(&AMT, writer).unwrap();
        let another = read(&*buffer).unwrap();
        if another != *AMT {
            panic!("serde inconsistent");
        }
    }
}
