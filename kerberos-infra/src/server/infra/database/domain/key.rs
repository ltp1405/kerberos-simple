use secrecy::Secret;

#[derive(Debug)]
pub struct Key {
    pub p_name: String,
    pub etype: i32,
    pub secret_key: Secret<String>,
    pub kvno: u64
}