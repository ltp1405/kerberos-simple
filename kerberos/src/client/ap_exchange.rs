use crate::client::client_env::ClientEnv;
use crate::client::client_error::ClientError;
use crate::cryptography::Cryptography;
use messages::basic_types::{EncryptedData, KerberosTime, Microseconds, NameTypes, PrincipalName};
use messages::{APOptions, ApReq, AuthenticatorBuilder, Encode};

pub fn prepare_ap_request(
    client_env: &impl ClientEnv,
    cryptography: &impl Cryptography,
    mutual_required: bool,
) -> Result<ApReq, ClientError> {
    let options = APOptions::new(true, mutual_required);
    let ticket = client_env.get_as_reply()?.ticket();

    let cname = PrincipalName::new(NameTypes::NtPrincipal, vec![client_env.get_client_name()?])?;
    let crealm = client_env.get_client_realm()?;
    let ctime = KerberosTime::from_unix_duration(client_env.get_current_time()?)?;
    let cusec = client_env.get_current_time()?.subsec_micros();
    let authenticator = AuthenticatorBuilder::default()
        .cname(cname)
        .crealm(crealm)
        .ctime(ctime)
        .cusec(Microseconds::try_from(cusec).expect("Invalid microseconds"))
        .build()?;

    let mut encoded_authenticator: Vec<u8> = Vec::new();
    authenticator.encode(encoded_authenticator.as_mut_slice())?;
    let encrypted_authenticator =
        cryptography.encrypt(&encoded_authenticator, &ticket.enc_part().key().key_value())?;
    let enc_authenticator = EncryptedData::new(
        ticket.enc_part().etype(),
        ticket.enc_part().kvno(),
        encrypted_authenticator,
    );
    let ap_req = ApReq::new(options, ticket.clone(), enc_authenticator);

    Ok(ap_req)
}
