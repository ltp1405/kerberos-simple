use std::time::Duration;

use der::{Decode, Encode};

use crate::basic::{
    ntypes, Int32, KerberosString, KerberosTime, Microseconds, PrincipalName, Realm,
};

use super::{ecodes, KrbErrorMsg};

#[test]
fn krb_err_builder_works_fine() {
    let stime = KerberosTime::from_unix_duration(Duration::from_secs(1615141775)).unwrap();
    let susec = Microseconds::new(&5.to_der().unwrap()).unwrap();
    let realm = Realm::new("EXAMPLE.COM").unwrap();
    let sname = {
        let name_type = ntypes::NT_ENTERPRISE;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::try_from(name_type, name_string).unwrap()
    };
    let error_code = Int32::new(&ecodes::KDC_ERROR_CLIENT_NOT_TRUSTED.to_der().unwrap()).unwrap();
    let krb_err = KrbErrorMsg::builder(
        stime,
        susec.clone(),
        error_code.clone(),
        realm.clone(),
        sname.clone(),
    )
    .build();
    assert_eq!(krb_err.stime(), &stime);
    assert_eq!(krb_err.susec(), &susec);
    assert_eq!(krb_err.error_code(), &error_code);
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
    let susec = Microseconds::new(&5.to_der().unwrap()).unwrap();
    let realm = Realm::new("EXAMPLE.COM").unwrap();
    let sname = {
        let name_type = ntypes::NT_ENTERPRISE;
        let name_string = vec![KerberosString::new("host").unwrap()];
        PrincipalName::try_from(name_type, name_string).unwrap()
    };
    let error_code = Int32::new(&ecodes::KDC_ERROR_CLIENT_NOT_TRUSTED.to_der().unwrap()).unwrap();
    let krb_err = KrbErrorMsg::builder(
        stime,
        susec.clone(),
        error_code.clone(),
        realm.clone(),
        sname.clone(),
    )
    .build();
    let bytes = krb_err.to_der().unwrap();
    let decoded = KrbErrorMsg::from_der(&bytes).unwrap();
    assert_eq!(decoded.stime(), &stime);
    assert_eq!(decoded.susec(), &susec);
    assert_eq!(decoded.error_code(), &error_code);
    assert_eq!(decoded.realm(), &realm);
    assert_eq!(decoded.sname(), &sname);
    assert!(decoded.cname().is_none());
    assert!(decoded.crealm().is_none());
    assert!(decoded.e_text().is_none());
    assert!(decoded.e_data().is_none());
}
