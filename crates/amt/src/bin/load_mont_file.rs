use std::time::Instant;
use std::{fs::File, path::Path};

use amt::amtp_file_name;
use amt::fast_serde;
use ark_bn254::Bn254;

fn main() {
    let start = Instant::now();

    let path = Path::new("./pp").join(amtp_file_name::<Bn254>(20, false, true));
    let file = File::open(path).unwrap();
    let params = fast_serde::read(file).unwrap();
    std::hint::black_box(params);

    let elapsed = start.elapsed();
    println!("Time elapsed {:?}", elapsed);
}
