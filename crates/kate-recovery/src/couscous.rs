use dusk_plonk::commitment_scheme::kzg10::PublicParameters;

const PP_BYTES: &'static [u8] = include_bytes!("../data/pp_1024.data");

pub fn public_params() -> PublicParameters {
    PublicParameters::from_slice(PP_BYTES)
        .expect("Deserialising of public parameters should work for serialised pp")
}
