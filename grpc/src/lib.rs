mod service;

pub use service::build_extension;
pub use service::{EncoderServer, EncoderService};

use std::net::SocketAddr;
use tonic::transport::Server;

const MESSAGE_SIZE_LIMIT: usize = 1024 * 1024 * 1024; // 1G

pub async fn run_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let encoder_service = EncoderService::new();
    Server::builder()
        .add_service(
            EncoderServer::new(encoder_service)
                .max_decoding_message_size(MESSAGE_SIZE_LIMIT)
                .max_encoding_message_size(MESSAGE_SIZE_LIMIT),
        )
        .serve(addr)
        .await?;
    Ok(())
}

// mod deprecated;
// pub use deprecated::{encoder::encoder_server::EncoderServer, EncoderService};
// #[macro_use]
// extern crate tracing;
