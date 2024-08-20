use der::{DateTime, Decode, Encode};
use fake::{Fake, Faker};
use rand::{Rng, SeedableRng};

use crate::basic::{
    ADEntry, AdAndOr, AdIfRelevant, AdKdcIssued, AdMandatoryForKdc, AddressTypes,
    AuthorizationData, Checksum, ETypeInfo, ETypeInfo2, ETypeInfo2Entry, ETypeInfoEntry,
    EncryptedData, EncryptionKey, Int32, KerberosString, KerberosTime, NameTypes,
    OctetString, PaData, PaEncTimestamp, PaEncTsEnc, PrincipalName, Realm, SequenceOf,
};

pub struct Scope<T> {
    pub entry: T,
    pub for_local: bool,
}

pub fn mock_etype_info2(seed: usize) -> ETypeInfo2 {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    let etype = rng.gen_range(0..100);
    let size = rng.gen_range(50..1000);
    let bytes = (0..size)
        .map(|_| rng.gen_range(0..128))
        .collect::<Vec<u8>>();
    let salt = KerberosString::new(&bytes).unwrap();
    let s2kparams = random_octet_string(seed);
    let mut entry = if rng.gen_bool(0.5) {
        ETypeInfo2Entry::new(etype.clone(), Some(salt.clone()), Some(s2kparams.clone()))
    } else {
        ETypeInfo2Entry::new(etype.clone(), None, Some(s2kparams.clone()))
    };
    if rng.gen_bool(0.5) {
        entry = ETypeInfo2Entry::new(etype, None, None);
    } else if rng.gen_range(0..100) > 50 {
        entry = ETypeInfo2Entry::new(etype, Some(salt), Some(s2kparams));
    }
    let etype_info = vec![entry];
    etype_info
}

pub fn mock_etype_info(seed: usize) -> ETypeInfo {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    let etype = rng.gen_range(0..100);
    let salt = random_octet_string(seed);
    let entry = if rng.gen_bool(0.5) {
        ETypeInfoEntry::new(etype, Some(salt))
    } else {
        ETypeInfoEntry::new(etype, None)
    };
    let etype_info = vec![entry];
    etype_info
}

pub fn mock_pa_enc_ts_enc(seed: usize) -> PaEncTsEnc {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    if rng.gen_bool(0.5) {
        PaEncTsEnc::now()
    } else {
        let mut pa_usec = None;
        if rng.gen_bool(0.5) {
            pa_usec = Some(rng.gen_range(0..100));
        }
        PaEncTsEnc::new(
            KerberosTime::from_date_time(DateTime::new(2023, 1, 1, 0, 0, 0).unwrap()),
            pa_usec,
        )
    }
}

pub fn mock_pa_enc_timestamp(seed: usize) -> PaEncTimestamp {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    let etype = rng.gen_range(0..100);
    let cipher = random_octet_string(seed);
    let mut kvno = None;
    if rng.gen_range(-100..100) > 0 {
        kvno = Some(rng.gen_range(0..100));
    }
    PaEncTimestamp::new(etype, kvno, cipher)
}

pub fn mock_ad_if_relevant_data() -> AdIfRelevant {
    let mut ad_if_relevant = AdIfRelevant::new();
    let mock_ad_entry = ADEntry::new(1, random_octet_string(12));
    ad_if_relevant.push(mock_ad_entry);
    ad_if_relevant
}

pub fn mock_ad_kdc_issue_data() -> [AdKdcIssued; 4] {
    let checksum = Checksum::new(1, random_octet_string(12));
    let mut auth = AuthorizationData::new();
    let mock_ad_entry = ADEntry::new(1, random_octet_string(12));
    auth.push(mock_ad_entry);
    let realm = Realm::new(b"\x00").unwrap();
    let data = vec![KerberosString::new(&Faker.fake::<String>()).unwrap()];
    let sname = PrincipalName::new(NameTypes::NtEnterprise, data).unwrap();
    [
        AdKdcIssued::new(
            checksum.clone(),
            Some(realm.clone()),
            Some(sname.clone()),
            auth.clone(),
        ),
        AdKdcIssued::new(checksum.clone(), Some(realm), None, auth.clone()),
        AdKdcIssued::new(checksum.clone(), None, Some(sname), auth.clone()),
        AdKdcIssued::new(checksum, None, None, auth),
    ]
}

pub fn mock_ad_and_or_data() -> AdAndOr {
    AdAndOr::new(1, AuthorizationData::new())
}

pub fn mock_ad_mandatory_for_kdc_data() -> AdMandatoryForKdc {
    let mut ad_if_relevant = AdMandatoryForKdc::new();
    let mock_ad_entry = ADEntry::new(1, random_octet_string(12));
    ad_if_relevant.push(mock_ad_entry);
    ad_if_relevant
}

pub fn generate_random_checksum(size: usize, seed: usize) -> Vec<Checksum> {
    let mut checksums = Vec::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    for _ in 0..size {
        let cktype = rng.gen_range(0..100);
        let ckvalue = random_octet_string(seed);
        checksums.push(Checksum::new(cktype, ckvalue));
    }
    checksums
}

pub fn generate_random_encryption_key(size: usize, seed: usize) -> Vec<EncryptionKey> {
    let mut keys = Vec::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    for _ in 0..size {
        let keytype = rng.gen_range(0..100);
        let keyvalue = random_octet_string(seed);
        keys.push(EncryptionKey::new(keytype, keyvalue));
    }
    keys
}

pub fn generate_random_encrypted_data(size: usize, seed: usize) -> Vec<EncryptedData> {
    let mut encrypted_data = Vec::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    for _ in 0..size {
        let etype = rng.gen_range(0..100);
        let cipher = random_octet_string(seed);
        let mut kvno = None;
        if rng.gen_range(-100..100) > 0 {
            kvno = Some(rng.gen_range(0..100));
        }
        let entry = EncryptedData::new(etype, kvno, cipher);
        encrypted_data.push(entry);
    }
    encrypted_data
}

pub fn generate_random_ad_entry(
    size: usize,
    seed: usize,
    f: fn(i32, &mut rand::rngs::StdRng) -> i32,
) -> Vec<ADEntry> {
    let mut entries = Vec::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    for _ in 0..size {
        let r: i32 = f(rng.gen(), &mut rng);
        let bytes = r.to_der().unwrap();
        let ad_data = match r {
            1 => OctetString::new(mock_ad_if_relevant_data().to_der().unwrap()).unwrap(),
            4 => OctetString::new(mock_ad_kdc_issue_data()[0].to_der().unwrap()).unwrap(),
            5 => OctetString::new(mock_ad_and_or_data().to_der().unwrap()).unwrap(),
            8 => OctetString::new(mock_ad_mandatory_for_kdc_data().to_der().unwrap()).unwrap(),
            _ => random_octet_string(seed),
        };
        let entry = ADEntry::new(Int32::from_der(&bytes).unwrap(), ad_data);
        entries.push(entry);
    }
    entries
}

pub fn generate_random_scope_pa(
    size: usize,
    seed: usize,
    f: fn(i32, &mut rand::rngs::StdRng) -> i32,
) -> Vec<Scope<PaData>> {
    let mut scopes = Vec::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    for _ in 0..size {
        let r: i32 = f(rng.gen(), &mut rng);
        let bytes = r.to_der().unwrap();
        let pa_data = PaData::new(Int32::from_der(&bytes).unwrap(), random_octet_string(seed));
        let for_local = r < 0;
        scopes.push(Scope {
            entry: pa_data,
            for_local,
        });
    }
    scopes
}

pub fn generate_random_scope_ad(size: usize, seed: usize) -> Vec<Scope<ADEntry>> {
    let mut scopes = Vec::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    for _ in 0..size {
        let r: i32 = rng.gen();
        let bytes = r.to_der().unwrap();
        let entry = ADEntry::new(Int32::from_der(&bytes).unwrap(), random_octet_string(seed));
        let for_local = r < 0;
        scopes.push(Scope { entry, for_local });
    }
    scopes
}

pub fn random_octet_string(seed: usize) -> OctetString {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    let len: usize = rng.gen::<usize>() % 1000;
    let mut octets = Vec::new();
    for _ in 0..len {
        octets.push(rng.gen::<u8>());
    }
    OctetString::new(octets).unwrap()
}

pub fn random_testcases_of_address_type(
    size: usize,
    seed: usize,
) -> Vec<(AddressTypes, OctetString)> {
    let mut testcases = Vec::new();
    let numbers = vec![2, 3, 5, 6, 7, 12, 16, 20, 24];
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
    for _ in 0..size {
        let idx: usize = rng.gen::<usize>() % numbers.len();
        let address_type = AddressTypes::from(numbers[idx]);
        let octet_string = random_octet_string(seed);
        testcases.push((address_type, octet_string));
    }
    testcases
}

pub fn random_testcases_of_principal_name_1(
    size: usize,
    empty: bool,
) -> Vec<(NameTypes, SequenceOf<KerberosString>)> {
    let numbers = vec![0, 1, 2, 3, 4, 5, 6, 7, 10];
    let mut testcases = Vec::new();
    for _ in 0..size {
        let idx: usize = rand::random::<usize>() % numbers.len();
        let name_type = NameTypes::from(numbers[idx]);
        if empty {
            continue;
        }
        testcases.push((name_type, random_seq_of_ker_str_len_1()));
    }
    testcases
}

pub fn random_testcases_of_principal_name_2(
    size: usize,
    empty: bool,
) -> Vec<(NameTypes, SequenceOf<KerberosString>)> {
    let mut testcases = Vec::new();
    let numbers = vec![0, 1, 2, 3, 4, 5, 6, 7, 10];
    for _ in 0..size {
        let idx: usize = rand::random::<usize>() % numbers.len();
        let name_type = NameTypes::from(numbers[idx]);
        if empty {
            continue;
        }
        testcases.push((name_type, random_seq_of_ker_str_len_2()));
    }
    testcases
}

fn random_seq_of_ker_str_len_1() -> SequenceOf<KerberosString> {
    let kerberos_strings = vec![KerberosString::new(&Faker.fake::<String>()).unwrap()];
    kerberos_strings
}

fn random_seq_of_ker_str_len_2() -> SequenceOf<KerberosString> {
    let mut kerberos_strings = SequenceOf::new();
    for _ in 0..2 {
        kerberos_strings.push(KerberosString::new(&Faker.fake::<String>()).unwrap());
    }
    kerberos_strings
}
