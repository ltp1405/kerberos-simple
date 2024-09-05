use crate::client::client_env::ClientEnv;
use crate::client::client_error::ClientError;
use crate::cryptography::Cryptography;
use messages::basic_types::{
    EncryptedData, KerberosTime, Microseconds, NameTypes, OctetString, PrincipalName,
};
use messages::{APOptions, ApReq, AuthenticatorBuilder, Decode, EncTicketPart, Encode};

pub fn prepare_ap_request(
    client_env: &impl ClientEnv,
    cryptography: &impl Cryptography,
    mutual_required: bool,
) -> Result<ApReq, ClientError> {
    let options = APOptions::new(true, mutual_required);
    let as_rep = client_env.get_as_reply()?;
    let ticket = as_rep.ticket();

    let cname = PrincipalName::new(NameTypes::NtPrincipal, vec![client_env.get_client_name()?])
        .map_err(|e| ClientError::GenericError(e.to_string()))?;
    let crealm = client_env.get_client_realm()?;
    let ctime = KerberosTime::from_unix_duration(client_env.get_current_time()?)
        .map_err(|e| ClientError::GenericError(e.to_string()))?;
    let cusec = client_env.get_current_time()?.subsec_micros();
    let authenticator = AuthenticatorBuilder::default()
        .cname(cname)
        .crealm(crealm)
        .ctime(ctime)
        .cusec(Microseconds::try_from(cusec).expect("Invalid microseconds"))
        // TODO: add checksum
        .build()?;

    let mut encoded_authenticator: Vec<u8> = Vec::new();
    authenticator
        .encode(&mut encoded_authenticator.as_mut_slice())
        .or(Err(ClientError::EncodeError))?;
    let mut decrypted_ticket_part = cryptography.decrypt(
        ticket.enc_part().cipher().as_ref(),
        client_env
            .get_client_key(*ticket.enc_part().etype())?
            .keyvalue()
            .as_ref(),
    )?;
    let ticket_part = EncTicketPart::from_der(decrypted_ticket_part.as_slice())
        .or(Err(ClientError::DecodeError))?;
    let encrypted_authenticator = cryptography.encrypt(
        &encoded_authenticator,
        ticket_part.key().keyvalue().as_ref(),
    )?;
    let enc_authenticator = EncryptedData::new(
        *ticket.enc_part().etype(),
        ticket.enc_part().kvno().map(|kvno| *kvno),
        OctetString::new(encrypted_authenticator).or(Err(ClientError::EncodeError))?,
    );
    let ap_req = ApReq::new(options, ticket.clone(), enc_authenticator);

    Ok(ap_req)
}
