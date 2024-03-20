use std::net::SocketAddr;

use service::{encoder::encoder_server::EncoderServer, EncoderService};
use tonic::transport::Server;

#[macro_use]
extern crate tracing;

mod service;

pub async fn run_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let encoder_service = EncoderService::new();
    Server::builder()
        .add_service(EncoderServer::new(encoder_service))
        .serve(addr)
        .await?;
    Ok(())
}
