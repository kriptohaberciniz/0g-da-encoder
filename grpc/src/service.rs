#![allow(unused)]

use tonic::{Code, Request, Response, Status};
use tracing::info;
use types::BlobLength;

pub mod encoder {
    tonic::include_proto!("encoder");
}

pub use encoder::encoder_server::EncoderServer;
use encoder::{encoder_server::Encoder, EncodeBlobReply, EncodeBlobRequest};

use amt::{EncoderContext, PowerTau};
use zg_encoder::{data_to_encoded_blob_amt, RawData, PE};

pub struct EncoderService {
    pp: PowerTau<PE>,
    context: EncoderContext<PE>,
}

impl EncoderService {
    pub fn new() -> Self {
        todo!()
    }
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
            "Received request from {:?}, data length: {:?}",
            remote_addr,
            request_content.data.len(),
        );

        let raw_data = RawData::try_from(&request_content.data[..])
            .map_err(|e| Status::new(Code::InvalidArgument, e))?;

        todo!()
    }
}

impl EncoderService {
    pub fn process_data(&self, raw_data: &RawData) -> Result<EncodeBlobReply, String> {
        let encoded_blob = data_to_encoded_blob_amt(raw_data, &self.pp, &self.context)?;

        Ok(todo!())
    }
}

pub fn build_extension(data: Vec<u8>, blob_length: BlobLength) -> Result<EncodeBlobReply, String> {
    todo!()
}
