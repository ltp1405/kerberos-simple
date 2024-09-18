use crate::client::client_env::ClientEnv;
use crate::client::client_error::ClientError;
use crate::cryptography::Cryptography;
use messages::basic_types::{
    Checksum, EncryptedData, KerberosTime, Microseconds, NameTypes, OctetString, PrincipalName,
};
use messages::{
    APOptions, ApRep, ApReq, Authenticator, AuthenticatorBuilder, Decode, EncApRepPart, Encode,
};
use rand::{thread_rng, Rng};

pub fn prepare_ap_request(
    client_env: &impl ClientEnv,
    mutual_required: bool,
    cksum_material: Option<Vec<u8>>,
) -> Result<ApReq, ClientError> {
    let options = APOptions::new(true, mutual_required);
    let tgs_rep = client_env.get_tgs_reply()?;

    let cname = PrincipalName::new(NameTypes::NtPrincipal, vec![client_env.get_client_name()?])
        .map_err(|e| ClientError::GenericError(e.to_string()))?;
    let crealm = client_env.get_client_realm()?;
    let ctime = KerberosTime::from_unix_duration(client_env.get_current_time()?)
        .map_err(|e| ClientError::GenericError(e.to_string()))?;
    let cusec = client_env.get_current_time()?.subsec_micros();
    let crypto_hash = client_env.get_checksum_hash(1)?;
    let mut authenticator = AuthenticatorBuilder::default();
    let mut rand = thread_rng();
    authenticator
        .seq_number(rand.gen::<u16>() as i32)
        .cname(cname)
        .crealm(crealm)
        .ctime(ctime)
        .cusec(Microseconds::try_from(cusec).expect("Invalid microseconds"));
    if let Some(cksum_material) = cksum_material {
        let cksum = Checksum::new(
            1,
            OctetString::new(crypto_hash.digest(cksum_material.as_slice()))
                .or(Err(ClientError::EncodeError))?,
        );
        authenticator.cksum(cksum);
    };
    let authenticator = authenticator.build()?;

    let encoded_authenticator = authenticator.to_der().or(Err(ClientError::EncodeError))?;
    let enc_part = client_env.get_tgs_reply_enc_part()?;
    let cryptography = client_env.get_crypto(*enc_part.key().keytype())?;
    let encrypted_authenticator = cryptography.encrypt(
        &encoded_authenticator,
        client_env
            .get_tgs_reply_enc_part()
            .unwrap()
            .key()
            .keyvalue()
            .as_ref(),
    )?;
    let enc_authenticator = EncryptedData::new(
        *enc_part.key().keytype(),
        1,
        OctetString::new(encrypted_authenticator).or(Err(ClientError::EncodeError))?,
    );
    let ap_req = ApReq::new(options, tgs_rep.ticket().clone(), enc_authenticator);

    Ok(ap_req)
}

pub fn prepare_pa_data(
    client_env: &impl ClientEnv,
    mutual_required: bool,
    cksum_material: Option<Vec<u8>>,
) -> Result<ApReq, ClientError> {
    let options = APOptions::new(true, mutual_required);
    let as_rep = client_env.get_as_reply()?;

    let cname = PrincipalName::new(NameTypes::NtPrincipal, vec![client_env.get_client_name()?])
        .map_err(|e| ClientError::GenericError(e.to_string()))?;
    let crealm = client_env.get_client_realm()?;
    let ctime = KerberosTime::from_unix_duration(client_env.get_current_time()?)
        .map_err(|e| ClientError::GenericError(e.to_string()))?;
    let cusec = client_env.get_current_time()?.subsec_micros();
    let crypto_hash = client_env.get_checksum_hash(1)?;
    let mut authenticator = AuthenticatorBuilder::default();
    let mut rand = thread_rng();
    authenticator
        .seq_number(rand.gen::<i32>())
        .cname(cname)
        .crealm(crealm)
        .ctime(ctime)
        .cusec(Microseconds::try_from(cusec).expect("Invalid microseconds"));
    if let Some(cksum_material) = cksum_material {
        let cksum = Checksum::new(
            1,
            OctetString::new(crypto_hash.digest(cksum_material.as_slice()))
                .or(Err(ClientError::EncodeError))?,
        );
        authenticator.cksum(cksum);
    };
    let authenticator = authenticator.build()?;

    let encoded_authenticator = authenticator.to_der().or(Err(ClientError::EncodeError))?;
    let enc_part = client_env.get_as_reply_enc_part()?;
    let cryptography = client_env.get_crypto(*enc_part.key().keytype())?;
    let encrypted_authenticator = cryptography.encrypt(
        &encoded_authenticator,
        client_env
            .get_as_reply_enc_part()
            .unwrap()
            .key()
            .keyvalue()
            .as_ref(),
    )?;
    let enc_authenticator = EncryptedData::new(
        *enc_part.key().keytype(),
        1,
        OctetString::new(encrypted_authenticator).or(Err(ClientError::EncodeError))?,
    );
    let ap_req = ApReq::new(options, as_rep.ticket().clone(), enc_authenticator);

    Ok(ap_req)
}

pub fn receive_ap_reply(
    client_env: &impl ClientEnv,
    cryptography: &impl Cryptography,
    ap_rep: ApRep,
    authenticator: Authenticator,
) -> Result<(), ClientError> {
    let binding = client_env.get_tgs_reply_enc_part()?;
    let session_key = binding.key();
    let ap_rep_part = EncApRepPart::from_der(
        cryptography
            .decrypt(
                ap_rep.enc_part().cipher().as_ref(),
                session_key.keyvalue().as_ref(),
            )?
            .as_ref(),
    )
    .or(Err(ClientError::DecodeError))?;

    if &authenticator.ctime() != ap_rep_part.ctime()
        || &authenticator.cusec() != ap_rep_part.cusec()
    {
        return Err(ClientError::MutualAuthenticationFailed);
    }
    if ap_rep_part.subkey().is_some() {
        client_env.save_subkey(ap_rep_part.subkey().unwrap().clone())?;
    }
    if ap_rep_part.seq_number().is_some() {
        client_env.save_seq_number(*ap_rep_part.seq_number().unwrap())?;
    }
    Ok(())
}
