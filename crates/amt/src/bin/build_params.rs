use std::{fs::File, path::Path};

use amt::amtp_file_name;
use amt::fast_serde;
use amt::EncoderContext;
use ark_bn254::Bn254;

fn main() {
    let ctx = EncoderContext::<Bn254>::new("./pp", 20, false);

    let path = Path::new("./pp").join(amtp_file_name::<Bn254>(20, false, true));
    let file = File::create(path).unwrap();
    fast_serde::write(&ctx.amt, file).unwrap();

    let path = Path::new("./pp").join(amtp_file_name::<Bn254>(20, true, true));
    let file = File::create(path).unwrap();
    fast_serde::write(&ctx.coset_amt, file).unwrap();
}
