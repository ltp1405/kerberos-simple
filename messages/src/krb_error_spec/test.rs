use std::time::Duration;

use der::{Decode, Encode};

use crate::krb_error_spec::Ecode;
use crate::{
    basic::{KerberosString, KerberosTime, NameTypes, PrincipalName, Realm},
    krb_error_spec::KrbErrorMsg,
    KrbErrorMsgBuilder,
};

#[test]
fn krb_err_builder_works_fine() {
    let stime = KerberosTime::from_unix_duration(Duration::from_secs(1615141775)).unwrap();
    let susec = 5;
    let realm = Realm::new("EXAMPLE.COM").unwrap();
    let sname = {
        let name_type = NameTypes::NtEnterprise;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::new(name_type, name_string).unwrap()
    };
    let error_code = Ecode::KDC_ERROR_CLIENT_NOT_TRUSTED;
    let krb_err = KrbErrorMsgBuilder::default()
        .stime(stime)
        .susec(susec.clone())
        .error_code(error_code)
        .realm(realm.clone())
        .sname(sname.clone())
        .build()
        .unwrap();
    assert_eq!(krb_err.stime(), &stime);
    assert_eq!(krb_err.susec(), &susec);
    assert_eq!(krb_err.error_code(), error_code);
    assert_eq!(krb_err.realm(), &realm);
    assert_eq!(krb_err.sname(), &sname);
    assert!(krb_err.cname().is_none());
    assert!(krb_err.crealm().is_none());
    assert!(krb_err.e_text().is_none());
    assert!(krb_err.e_data().is_none());
}

#[test]
fn encode_decode_for_krb_err_msg_works_fine() {
    let stime = KerberosTime::from_unix_duration(Duration::from_secs(1615141775)).unwrap();
    let susec = 5;
    let realm = Realm::new("EXAMPLE.COM").unwrap();
    let sname = {
        let name_type = NameTypes::NtEnterprise;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::new(name_type, name_string).unwrap()
    };
    let error_code = Ecode::KDC_ERROR_CLIENT_NOT_TRUSTED;
    let krb_err = KrbErrorMsgBuilder::default()
        .stime(stime)
        .susec(susec.clone())
        .error_code(error_code)
        .realm(realm.clone())
        .sname(sname.clone())
        .build()
        .unwrap();
    let bytes = krb_err.to_der().unwrap();
    let decoded = KrbErrorMsg::from_der(&bytes).unwrap();
    assert_eq!(decoded.stime(), &stime);
    assert_eq!(decoded.susec(), &susec);
    assert_eq!(decoded.error_code(), error_code);
    assert_eq!(decoded.realm(), &realm);
    assert_eq!(decoded.sname(), &sname);
    assert!(decoded.cname().is_none());
    assert!(decoded.crealm().is_none());
    assert!(decoded.e_text().is_none());
    assert!(decoded.e_data().is_none());
}
