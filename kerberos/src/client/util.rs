use rand::Rng;

pub(crate) fn generate_nonce() -> u32 {
    let mut rng = rand::thread_rng();
    rng.gen()
}