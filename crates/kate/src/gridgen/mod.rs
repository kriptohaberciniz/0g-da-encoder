use crate::pmp::{
    ark_poly::{EvaluationDomain, GeneralEvaluationDomain},
    m1_blst::{Bls12_381, M1NoPrecomp},
    merlin::Transcript,
    traits::Committer,
};

use core::{
    cmp::{max, min},
    iter,
    num::NonZeroU16,
};
use kate_recovery::matrix::Dimensions;
use nalgebra::base::DMatrix;
use poly_multiproof::{
    m1_blst::Proof,
    traits::{KZGProof, PolyMultiProofNoPrecomp},
};

use static_assertions::const_assert;

use thiserror_no_std::Error;
use zerog_core::{ensure, AppId};

use crate::{
    com::{Cell, Error},
    config::DATA_CHUNK_SIZE,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

macro_rules! cfg_iter {
    ($e: expr) => {{
        #[cfg(feature = "parallel")]
        let result = $e.par_iter();
        #[cfg(not(feature = "parallel"))]
        let result = $e.iter();
        result
    }};
}

pub const SCALAR_SIZE: usize = 32;
pub type ArkScalar = crate::pmp::m1_blst::Fr;
pub type Commitment = crate::pmp::Commitment<Bls12_381>;
pub use poly_multiproof::traits::AsBytes;

pub struct EvaluationGrid {
    evals: DMatrix<ArkScalar>,
}

#[derive(Error, Debug, Clone, Copy)]
pub enum AppRowError {
    #[error("Original dimensions are not divisible by current ones")]
    OrigDimNotDivisible,
    #[error("AppId({0}) not found")]
    IdNotFound(AppId),
    #[error("Lineal index overflows")]
    LinealIndexOverflows,
}

impl EvaluationGrid {
    /// From the app extrinsics, create a data grid of Scalars
    pub fn from_data(
        data: Vec<u8>,
        min_width: usize,
        max_width: usize,
        max_height: usize,
    ) -> Result<Self, Error> {
        // convert data to scalars
        let scalars = data
            .chunks(DATA_CHUNK_SIZE)
            .map(pad_to_bls_scalar)
            .collect::<Result<Vec<_>, _>>()?;
        // compute grid size
        let grid_size = scalars.len();
        let (rows, cols): (usize, usize) =
            get_block_dims(grid_size, min_width, max_width, max_height)?.into();
        // Flatten the grid
        let grid = scalars.into_iter().chain(iter::repeat(0).map(|_| {
            let zero_values: [u8; SCALAR_SIZE - 1] = [0; SCALAR_SIZE - 1];
            pad_to_bls_scalar(zero_values).expect("less than SCALAR_SIZE values, can't fail")
        }));

        let row_major_evals = DMatrix::from_row_iterator(rows, cols, grid);

        Ok(EvaluationGrid {
            evals: row_major_evals,
        })
    }

    /// Get the row `y` of the evaluation.
    pub fn row(&self, y: usize) -> Option<Vec<ArkScalar>> {
        let (rows, _cols) = self.evals.shape();
        (y < rows).then(|| self.evals.row(y).iter().cloned().collect())
    }

    pub fn dims(&self) -> Dimensions {
        let (rows, cols) = self.evals.shape();
        // SAFETY: We cannot construct an `EvaluationGrid` with any dimension `< 1` or `> u16::MAX`
        debug_assert!(rows <= usize::from(u16::MAX) && cols <= usize::from(u16::MAX));
        unsafe { Dimensions::new_unchecked(rows as u16, cols as u16) }
    }

    #[inline]
    pub fn get<R, C>(&self, row: R, col: C) -> Option<&ArkScalar>
    where
        usize: From<R>,
        usize: From<C>,
    {
        self.evals.get::<(usize, usize)>((row.into(), col.into()))
    }

    pub fn extend_columns(&self, row_factor: NonZeroU16) -> Result<Self, Error> {
        let dims = self.dims();
        let (new_rows, new_cols): (usize, usize) = dims
            .extend(row_factor, unsafe { NonZeroU16::new_unchecked(1) })
            .ok_or(Error::CellLengthExceeded)?
            .into();
        let (rows, _cols): (usize, usize) = dims.into();

        let domain =
            GeneralEvaluationDomain::<ArkScalar>::new(rows).ok_or(Error::DomainSizeInvalid)?;
        let domain_new =
            GeneralEvaluationDomain::<ArkScalar>::new(new_rows).ok_or(Error::DomainSizeInvalid)?;
        ensure!(domain_new.size() == new_rows, Error::DomainSizeInvalid);

        let new_data = self.evals.column_iter().flat_map(|col| {
            let mut col = col.iter().cloned().collect::<Vec<_>>();
            domain.ifft_in_place(&mut col);
            domain_new.fft_in_place(&mut col);
            col
        });

        let row_major_evals = DMatrix::from_iterator(new_rows, new_cols, new_data);
        debug_assert!(row_major_evals.shape() == (new_rows, new_cols));
        Ok(Self {
            evals: row_major_evals,
        })
    }

    pub fn make_polynomial_grid(&self) -> Result<PolynomialGrid, Error> {
        let (_rows, cols): (usize, usize) = self.evals.shape();
        let domain =
            GeneralEvaluationDomain::<ArkScalar>::new(cols).ok_or(Error::DomainSizeInvalid)?;

        let inner = self
            .evals
            .row_iter()
            .map(|view| {
                let row = view.iter().cloned().collect::<Vec<_>>();
                domain.ifft(&row)
            })
            .collect::<Vec<_>>();

        Ok(PolynomialGrid {
            dims: self.dims(),
            points: domain.elements().collect(),
            inner,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut result = vec![];
        for row in self.evals.row_iter() {
            for scalar in row.iter() {
                result.extend(scalar.to_bytes().map_err(|e| format!("{:?}", e))?);
            }
        }
        Ok(result)
    }

    pub fn from_row_slices(nrows: usize, ncols: usize, data: Vec<u8>) -> Result<Self, Error> {
        if nrows * ncols * SCALAR_SIZE != data.len() {
            return Err(Error::DimensionsMismatch);
        }
        let scalars = data
            .chunks(SCALAR_SIZE)
            .map(|buf| {
                ArkScalar::from_bytes(buf.try_into().unwrap()).map_err(Error::MultiproofError)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            evals: DMatrix::from_row_iterator(nrows, ncols, scalars.into_iter()),
        })
    }
}

pub struct PolynomialGrid {
    inner: Vec<Vec<ArkScalar>>,
    points: Vec<ArkScalar>,
    dims: Dimensions,
}

impl PolynomialGrid {
    pub fn commitments(
        &self,
        srs: &(impl Committer<Bls12_381> + Sync),
    ) -> Result<Vec<Commitment>, Error> {
        cfg_iter!(self.inner)
            .map(|poly| srs.commit(poly).map_err(Error::MultiproofError))
            .collect()
    }

    /// Computes the commitments of the grid for the given extension by committing, then fft-ing
    /// the commitments.
    // TODO: fix this all up without the gross conversions after moving to arkworks
    pub fn extended_commitments(
        &self,
        srs: &(impl Committer<Bls12_381> + Sync),
        extension_factor: usize,
    ) -> Result<Vec<Commitment>, Error> {
        let res = cfg_iter!(self.inner)
            .map(|coeffs| srs.commit(coeffs).map_err(Error::MultiproofError))
            .collect::<Result<Vec<_>, _>>()?;
        poly_multiproof::Commitment::<Bls12_381>::extend_commitments(
            &res,
            res.len().saturating_mul(extension_factor),
        )
        .map_err(Error::MultiproofError)
    }

    pub fn commitment(
        &self,
        srs: &impl Committer<Bls12_381>,
        row: usize,
    ) -> Result<Commitment, Error> {
        self.inner
            .get(row)
            .ok_or(Error::CellLengthExceeded)
            .and_then(|poly| srs.commit(poly).map_err(Error::MultiproofError))
    }

    pub fn proof(&self, srs: &M1NoPrecomp, cell: &Cell) -> Result<Proof, Error> {
        let x = cell.col.0 as usize;
        let y = cell.row.0 as usize;
        let poly = self.inner.get(y).ok_or(Error::CellLengthExceeded)?;
        let witness = KZGProof::compute_witness_polynomial(srs, poly.clone(), self.points[x])?;
        Ok(KZGProof::open(srs, witness)?)
    }

    pub fn multiproof(
        &self,
        srs: &M1NoPrecomp,
        cell: &Cell,
        eval_grid: &EvaluationGrid,
        target_dims: Dimensions,
    ) -> Result<Multiproof, Error> {
        let block = multiproof_block(
            cell.col.0 as usize,
            cell.row.0 as usize,
            self.dims,
            target_dims,
        )
        .ok_or(Error::CellLengthExceeded)?;
        let polys = &self.inner[block.start_y..block.end_y];
        let evals: Vec<Vec<ArkScalar>> = (block.start_y..block.end_y)
            .map(|y| {
                eval_grid.row(y).expect("Already bounds checked .qed")[block.start_x..block.end_x]
                    .to_vec()
            })
            .collect::<Vec<_>>();
        let evals_view = evals.iter().map(|row| row.as_slice()).collect::<Vec<_>>();

        let points = &self.points[block.start_x..block.end_x];
        let mut ts = Transcript::new(b"avail-mp");
        let proof = PolyMultiProofNoPrecomp::open(srs, &mut ts, &evals_view, polys, points)
            .map_err(Error::MultiproofError)?;

        Ok(Multiproof {
            proof,
            evals,
            block,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Multiproof {
    pub proof: poly_multiproof::m1_blst::Proof,
    pub evals: Vec<Vec<poly_multiproof::m1_blst::Fr>>,
    pub block: CellBlock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellBlock {
    pub start_x: usize,
    pub start_y: usize,
    pub end_x: usize,
    pub end_y: usize,
}

/// Computes the `x, y`-th multiproof block of a grid of size `grid_dims`.
/// `mp_grid_dims` is the size of the multiproof grid, which `x,y` lies in.
/// For example, a 256x256 grid could be converted to a 4x4 target size multiproof grid, by making 16 multiproofs
/// of size 64x64.
#[allow(clippy::arithmetic_side_effects)]
pub fn multiproof_block(
    x: usize,
    y: usize,
    grid: Dimensions,
    target: Dimensions,
) -> Option<CellBlock> {
    let mp_grid_dims = multiproof_dims(grid, target)?;
    let (g_rows, g_cols): (usize, usize) = grid.into();
    if x >= mp_grid_dims.width() || y >= mp_grid_dims.height() {
        return None;
    }

    // SAFETY: Division is safe because `cols() != 0 && rows() != 0`.
    let block_width = g_cols / usize::from(NonZeroU16::get(mp_grid_dims.cols()));
    let block_height = g_rows / usize::from(NonZeroU16::get(mp_grid_dims.rows()));

    // SAFETY: values never overflow since `x` and `y` are always less than grid_dims.{width,height}().
    // This is because x,y < mp_grid_dims.{width, height} and block width is the quotient of
    // grid_dims and mp_grid_dims.
    Some(CellBlock {
        start_x: x * block_width,
        start_y: y * block_height,
        end_x: (x + 1) * block_width,
        end_y: (y + 1) * block_height,
    })
}

/// Dimensions of the multiproof grid. These are guarenteed to cleanly divide `grid_dims`.
/// `target_dims` must cleanly divide `grid_dims`.
#[allow(clippy::arithmetic_side_effects)]
pub fn multiproof_dims(grid: Dimensions, target: Dimensions) -> Option<Dimensions> {
    let cols = min(grid.cols(), target.cols());
    let rows = min(grid.rows(), target.rows());
    if grid.cols().get() % cols != 0 || grid.rows().get() % rows != 0 {
        return None;
    }

    Dimensions::new(rows, cols)
}

pub fn get_block_dims(
    n_scalars: usize,
    min_width: usize,
    max_width: usize,
    max_height: usize,
) -> Result<Dimensions, Error> {
    // Less than max_width wide block
    if n_scalars < max_width {
        let current_width = n_scalars;
        // Don't let the width get lower than the minimum provided
        let width = max(
            current_width
                .checked_next_power_of_two()
                .ok_or(Error::BlockTooBig)?,
            min_width,
        );
        let height = unsafe { NonZeroU16::new_unchecked(1) };

        Dimensions::new_from(height, width).ok_or(Error::ZeroDimension)
    } else {
        let width = NonZeroU16::try_from(u16::try_from(max_width)?)?;
        let current_height = round_up_to_multiple(n_scalars, width)
            .checked_div(max_width)
            .expect("`max_width` is non zero, checked one line before");
        // Round the height up to a power of 2 for ffts
        let height = current_height
            .checked_next_power_of_two()
            .ok_or(Error::BlockTooBig)?;
        // Error if height too big
        ensure!(height <= max_height, Error::BlockTooBig);

        Dimensions::new_from(height, width).ok_or(Error::ZeroDimension)
    }
}

pub fn domain_points(n: usize) -> Result<Vec<ArkScalar>, Error> {
    let domain = GeneralEvaluationDomain::<ArkScalar>::new(n).ok_or(Error::DomainSizeInvalid)?;
    Ok(domain.elements().collect())
}

/// SAFETY: As `multiple` is a `NonZeroU16` we can safetly make the following ops.
#[allow(clippy::arithmetic_side_effects)]
fn round_up_to_multiple(input: usize, multiple: NonZeroU16) -> usize {
    let multiple: usize = multiple.get().into();
    let n_multiples = input.saturating_add(multiple - 1) / multiple;
    n_multiples.saturating_mul(multiple)
}

pub(crate) fn pad_to_bls_scalar(a: impl AsRef<[u8]>) -> Result<ArkScalar, Error> {
    let bytes = a.as_ref();
    ensure!(bytes.len() <= DATA_CHUNK_SIZE, Error::InvalidChunkLength);
    const_assert!(DATA_CHUNK_SIZE <= SCALAR_SIZE);

    let mut buf = [0u8; SCALAR_SIZE];
    buf[0..bytes.len()].copy_from_slice(bytes);

    ArkScalar::from_bytes(&buf).map_err(Error::MultiproofError)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod unit_tests {
    use super::*;
    use proptest::{prop_assert_eq, proptest};
    use test_case::test_case;

    // parameters that will split a 256x256 grid into pieces of size 4x16
    const TARGET: Dimensions = unsafe { Dimensions::new_unchecked(16, 64) };
    const GRID: Dimensions = unsafe { Dimensions::new_unchecked(256, 256) };

    fn cb(start_x: usize, start_y: usize, end_x: usize, end_y: usize) -> CellBlock {
        CellBlock {
            start_x,
            start_y,
            end_x,
            end_y,
        }
    }
    #[test_case(0, 0 => Some(cb(0, 0, 4, 16)))]
    #[test_case(1, 0 => Some(cb(4, 0, 8, 16)))]
    #[test_case(0, 1 => Some(cb(0, 16, 4, 32)))]
    #[test_case(1, 1 => Some(cb(4, 16, 8, 32)))]
    #[test_case(64, 0 => None)]
    #[test_case(0, 16 => None)]
    fn multiproof_max_grid_size(x: usize, y: usize) -> Option<CellBlock> {
        multiproof_block(x, y, GRID, TARGET)
    }

    #[test_case(256, 256,  64,  16 => Some((64, 16)))]
    #[test_case(256, 256,  32,  32 => Some((32, 32)))]
    #[test_case(256, 256,   7,  32 => None)]
    #[test_case(32 ,  32,  32,  32 => Some((32, 32)))]
    #[test_case(256,   8,  32,  32 => Some((32, 8)))]
    #[test_case(4  ,   1,  32,  32 => Some((4, 1)))]
    fn test_multiproof_dims(
        grid_w: u16,
        grid_h: u16,
        target_w: u16,
        target_h: u16,
    ) -> Option<(usize, usize)> {
        let grid = unsafe { Dimensions::new_unchecked(grid_w, grid_h) };
        let target = unsafe { Dimensions::new_unchecked(target_w, target_h) };

        multiproof_dims(grid, target).map(Into::into)
    }

    use proptest::prelude::*;
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 200, .. ProptestConfig::default()
          })]
        #[test]
        fn test_round_up_to_multiple(i in 1..1000usize, m in 1..32u16) {
            for k in 0..usize::from(m) {
                let a :usize = i * usize::from(m) - k;
                let output = round_up_to_multiple(a, m.try_into().unwrap());
                let expected :usize = i * usize::from(m);
                prop_assert_eq!( output, expected)
            }
        }
    }
    #[test_case(0 => 1)]
    #[test_case(1 => 1)]
    #[test_case(2 => 2)]
    #[test_case(3 => 4)]
    #[test_case(6 => 8)]
    #[test_case(972 => 1024)]
    fn test_round_up_to_2(i: usize) -> usize {
        i.next_power_of_two()
    }

    fn new_dim(rows: u16, cols: u16) -> Result<Dimensions, Error> {
        Dimensions::new(rows, cols).ok_or(Error::BlockTooBig)
    }

    #[test_case(0 => new_dim(1,4) ; "block size zero")]
    #[test_case(1 => new_dim(1,4) ; "below minimum block size")]
    #[test_case(10 => new_dim(1, 16) ; "regular case")]
    #[test_case(17 => new_dim(1, 32) ; "minimum overhead after 512")]
    #[test_case(256 => new_dim(1, 256) ; "maximum cols")]
    #[test_case(257 => new_dim(2, 256) ; "two rows")]
    #[test_case(256 * 256 => new_dim(256, 256) ; "max block size")]
    #[test_case(256 * 256 + 1 => Err(Error::BlockTooBig) ; "too much data")]
    fn test_get_block_dims(size: usize) -> Result<Dimensions, Error>
where {
        get_block_dims(size, 4, 256, 256)
    }
}
