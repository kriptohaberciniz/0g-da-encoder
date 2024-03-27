#[macro_use]
extern crate tracing;

use std::{error::Error, str::FromStr, time::Duration};

use grpc::EncoderService;

use tokio::time::{sleep_until, Instant};
use tracing::Level;

use types::BlobLength;

const N: usize = 64;
const RPS: u32 = 2;
const BLOB_SIZE: usize = 31 * 512 * 1024;
const MAX_COLS: u32 = 1024;
const MAX_ROWS: u32 = 2048;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // enable backtraces
    std::env::set_var("RUST_BACKTRACE", "1");
    tracing_subscriber::fmt()
        .with_max_level(Level::from_str("info").unwrap())
        .init();

    let (response_tx, mut response_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut broadcast_txs = vec![];
    for _ in 0..N {
        let (task_tx, mut task_rx) = tokio::sync::mpsc::unbounded_channel();
        let tx = response_tx.clone();
        tokio::spawn(async move {
            let service = EncoderService::new();
            while let Some(id) = task_rx.recv().await {
                let mut data = vec![];
                for _ in 0..BLOB_SIZE {
                    data.push(rand::random());
                }
                let ts = Instant::now();
                if let Err(e) = service.build_extension(
                    data,
                    BlobLength {
                        cols: MAX_COLS,
                        rows: MAX_ROWS,
                    },
                ) {
                    error!("task #{:?} failed, error: {:?}", id, e);
                }
                let delay = ts.elapsed().as_millis();
                info!("task #{:?} done. time elapsed: {:?}ms.", id, delay);
                if let Err(e) = tx.send(delay) {
                    info!("failed to send response #{:?}: {:?}", id, e);
                }
            }
        });
        broadcast_txs.push(task_tx);
    }

    tokio::spawn(async move {
        let mut cnt = 0;
        let mut used = 0;
        let mut max_delay = 0;
        let ts = Instant::now();
        while let Some(delay) = response_rx.recv().await {
            used += delay;
            cnt += 1;
            if delay > max_delay {
                max_delay = delay;
            }
            if cnt % 10 == 0 {
                info!(
					"time elapsed: {:?}s, total finished task: {:?}, average/max delay: {:?}/{:?} ms",
					ts.elapsed().as_secs(),
					cnt,
					used / cnt,
					max_delay
				);
            }
        }
    });

    let mut id = 0;
    let mut thread_id = 0;
    let mut ts = Instant::now();
    loop {
        for _ in 0..RPS {
            id += 1;
            if let Err(e) = broadcast_txs[thread_id].send(id) {
                info!("failed to send task #{:?}: {:?}", id, e);
            }
            info!("task #{:?} sent to thread #{:?}", id, thread_id);
            thread_id = (thread_id + 1) % N;
        }
        ts += Duration::from_secs(1);
        sleep_until(ts).await;
    }
}
