use encoder::encoder_server::Encoder;
use tonic::{Request, Response, Status};
use types::BlobLength;

use self::encoder::{EncodeBlobReply, EncodeBlobRequest};

pub mod encoder {
    tonic::include_proto!("encoder");
}

pub use encoder::encoder_server::EncoderServer;

pub struct EncoderService;

impl EncoderService {
    pub fn new() -> Self {
        EncoderService
    }
}

#[tonic::async_trait]
#[allow(unused)]
impl Encoder for EncoderService {
    async fn encode_blob(
        &self,
        request: Request<EncodeBlobRequest>,
    ) -> Result<Response<EncodeBlobReply>, Status> {
        todo!()
    }
}

pub fn build_extension(
    data: Vec<u8>,
    blob_length: BlobLength,
) -> Result<EncodeBlobReply, String> {
    todo!()
}