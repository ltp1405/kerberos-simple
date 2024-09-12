use secrecy::Secret;

#[derive(Debug)]
pub struct PrincipalComplexView {
    pub principal_name: String,
    pub realm: String,
    pub max_renewable_life: i64,
    pub max_lifetime: i64,
    pub key: Secret<String>,
    pub p_kvno: i32,
    pub supported_enctypes: Vec<i32>,
}