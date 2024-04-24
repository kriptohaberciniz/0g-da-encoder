use std::num::NonZeroU16;

use encoder::encoder_server::Encoder;
use kate::{
    config::{MAX_BLOCK_COLUMNS, MAX_BLOCK_ROWS},
    gridgen::EvaluationGrid,
};
use tonic::{Code, Request, Response, Status};
use types::BlobLength;

use self::encoder::{EncodeBlobReply, EncodeBlobRequest};

pub mod encoder {
    tonic::include_proto!("encoder");
}

pub struct EncoderService {
    limits: BlobLength,
}

#[tonic::async_trait]
impl Encoder for EncoderService {
    async fn encode_blob(
        &self,
        request: Request<EncodeBlobRequest>,
    ) -> Result<Response<EncodeBlobReply>, Status> {
        let remote_addr = request.remote_addr();
        let request_content = request.into_inner();
        info!(
            "Received request from {:?}, data length: {:?}, target cols: {:?}",
            remote_addr,
            request_content.data.len(),
            request_content.cols,
        );
        // align blob length
        match self.get_cols(request_content.cols) {
            Ok(cols) => {
                match self.build_extension(
                    request_content.data,
                    BlobLength {
                        cols,
                        rows: self.limits.rows,
                    },
                ) {
                    Ok(reply) => Ok(Response::new(reply)),
                    Err(msg) => {
                        return Err(Status::new(Code::Internal, msg));
                    }
                }
            }
            Err(msg) => {
                return Err(Status::new(Code::InvalidArgument, msg));
            }
        }
    }
}

impl Default for EncoderService {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderService {
    pub fn new() -> Self {
        EncoderService {
            limits: BlobLength {
                cols: MAX_BLOCK_ROWS.0,
                rows: MAX_BLOCK_COLUMNS.0,
            },
        }
    }

    fn get_cols(&self, requested_cols: u32) -> Result<u32, String> {
        if let Some(aligned_cols) = requested_cols.checked_next_power_of_two() {
            if aligned_cols <= self.limits.cols {
                Ok(aligned_cols)
            } else {
                Ok(self.limits.cols)
            }
        } else {
            Err("cols too large".to_owned())
        }
    }

    fn build_grid(&self, data: Vec<u8>, blob_length: BlobLength) -> Result<EvaluationGrid, String> {
        const MIN_WIDTH: usize = 4;
        let grid = EvaluationGrid::from_data(
            data,
            MIN_WIDTH,
            blob_length.cols as usize,
            blob_length.rows as usize,
        )
        .map_err(|e| format!("Grid construction failed: {e:?}"))?;

        Ok(grid)
    }

    pub fn build_commitment(&self, grid: &EvaluationGrid) -> Result<Vec<u8>, String> {
        use kate::gridgen::AsBytes;
        use once_cell::sync::Lazy;

        // couscous has pp for degree upto 1024
        static PMP: Lazy<kate::pmp::m1_blst::M1NoPrecomp> =
            Lazy::new(kate::couscous::multiproof_params);

        let poly_grid = grid
            .make_polynomial_grid()
            .map_err(|e| format!("Make polynomial grid failed: {e:?}"))?;

        let extended_grid = poly_grid
            .extended_commitments(&*PMP, 2)
            .map_err(|e| format!("Grid extension failed: {e:?}"))?;

        let mut commitment = Vec::new();
        for c in extended_grid.iter() {
            match c.to_bytes() {
                Ok(bytes) => commitment.extend(bytes),
                Err(e) => return Err(format!("Commitment serialization failed: {:?}", e)),
            }
        }

        Ok(commitment)
    }

    pub fn build_extension(
        &self,
        data: Vec<u8>,
        blob_length: BlobLength,
    ) -> Result<EncodeBlobReply, String> {
        // Build the grid
        let mut timer = std::time::Instant::now();
        let maybe_grid = self.build_grid(data, blob_length);
        let grid = match maybe_grid {
            Ok(res) => {
                info!("build grid used {:?}ms", timer.elapsed().as_millis());
                timer = std::time::Instant::now();
                res
            }
            Err(message) => {
                error!("NODE_CRITICAL_ERROR_001 - A critical error has occurred: {message:?}.");
                return Err(format!("Error building grids: {:?}", message));
            }
        };

        // Build the commitment
        let maybe_commitment = self.build_commitment(&grid);
        let commitment = match maybe_commitment {
            Ok(res) => {
                info!("build commitment used {:?}ms", timer.elapsed().as_millis());
                timer = std::time::Instant::now();
                res
            }
            Err(message) => {
                error!("NODE_CRITICAL_ERROR_002 - A critical error has occurred: {message:?}.");
                return Err(format!("Error building commitments: {:?}", message));
            }
        };

        // Note that this uses the original dims, _not the extended ones_

        match grid.extend_columns(NonZeroU16::new(2).expect("2>0")) {
            Ok(extended_grid) => {
                let rows = extended_grid.dims().rows().get();
                let cols = extended_grid.dims().cols().get();
                info!(
                    "extend grid used {:?}ms, extended matrix dims: {:?}x{:?}.",
                    timer.elapsed().as_millis(),
                    rows,
                    cols
                );
                Ok(EncodeBlobReply {
                    rows: rows.into(),
                    cols: cols.into(),
                    commitment,
                    chunks: extended_grid.to_bytes()?,
                })
            }
            Err(message) => Err(format!("Error extending grid: {:?}", message)),
        }
    }
}
