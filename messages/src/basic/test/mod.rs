use der::{Decode, Encode};
use fake::{Fake, Faker};
use rand::Rng;
use utils::{
    generate_random_ad_entry, generate_random_checksum, generate_random_encrypted_data,
    generate_random_encryption_key, generate_random_scope_ad, generate_random_scope_pa,
    mock_ad_and_or_data, mock_ad_if_relevant_data, mock_ad_kdc_issue_data,
    mock_ad_mandatory_for_kdc_data, mock_etype_info, mock_etype_info2, mock_pa_enc_timestamp,
    mock_pa_enc_ts_enc, random_testcases_of_address_type, random_testcases_of_principal_name_1,
    random_testcases_of_principal_name_2, Scope,
};

use crate::basic::{
    ADRegisteredEntry, AdAndOr, AdIfRelevant, AdMandatoryForKdc, ETypeInfo, ETypeInfo2,
    PaDataRegisteredType, PaEncTimestamp, PaEncTsEnc,
};

use super::{
    ADEntry, AdKdcIssued, Checksum, EncryptedData, EncryptionKey, HostAddress, KerberosFlags,
    KerberosFlagsOption, PaData, PrincipalName,
};

mod utils;

////////////////////////// PrincipalName //////////////////////////
#[test]
fn principal_name_works_fine_with_appropriate_seq_of_ker_strs() {
    let testcases = random_testcases_of_principal_name_1(10, false);

    for (expected_name_type, name_string) in testcases {
        let principal_name = PrincipalName::new(expected_name_type, name_string.clone());
        assert!(principal_name.is_ok());
        let principal_name = principal_name.unwrap();
        assert_eq!(principal_name.name_type(), expected_name_type);
        assert_eq!(principal_name.name_string(), &name_string);
    }

    let testcases = random_testcases_of_principal_name_2(12, false);

    for (expected_name_type, name_string) in testcases {
        let principal_name = PrincipalName::new(expected_name_type, name_string.clone());
        assert!(principal_name.is_ok());
        let principal_name = principal_name.unwrap();
        assert_eq!(principal_name.name_type(), expected_name_type);
        assert_eq!(principal_name.name_string(), &name_string);
    }
}

#[test]
fn principal_name_fails_with_inappropriate_seq_of_ker_strs() {
    let testcases = random_testcases_of_principal_name_1(9, true);

    for (expected_name_type, name_string) in testcases {
        let principal_name = PrincipalName::new(expected_name_type, name_string.clone());
        assert!(principal_name.is_err());
    }

    let testcases = random_testcases_of_principal_name_2(3, true);

    for (expected_name_type, name_string) in testcases {
        let principal_name = PrincipalName::new(expected_name_type, name_string.clone());
        assert!(principal_name.is_err());
    }
}

#[test]
fn encode_decode_for_principal_name_works_fine() {
    let testcases = random_testcases_of_principal_name_1(12, false);

    for (expected_name_type, name_string) in testcases {
        let principal_name = PrincipalName::new(expected_name_type, name_string.clone());
        assert!(
            principal_name.is_ok(),
            "Failed to create: {:?}",
            principal_name
        );
        let principal_name = principal_name.unwrap();
        let encoded = principal_name.to_der();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);
        let encoded = encoded.unwrap();
        let decoded = PrincipalName::from_der(&encoded);
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);
        let decoded = decoded.unwrap();
        assert_eq!(decoded, principal_name);
    }

    let testcases = random_testcases_of_principal_name_2(20, false);

    for (expected_name_type, name_string) in testcases {
        let principal_name = PrincipalName::new(expected_name_type, name_string.clone());
        assert!(
            principal_name.is_ok(),
            "Failed to create: {:?}",
            principal_name
        );
        let principal_name = principal_name.unwrap();
        let encoded = principal_name.to_der();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);
        let encoded = encoded.unwrap();
        let decoded = PrincipalName::from_der(&encoded);
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);
        let decoded = decoded.unwrap();
        assert_eq!(decoded, principal_name);
    }
}

////////////////////////// HostAddress //////////////////////////
#[test]
fn getter_of_host_address_works_fine() {
    let testcases = random_testcases_of_address_type(20, 29);
    for (address_type, address) in testcases {
        let host_address = HostAddress::new(address_type, address.clone());
        assert_eq!(host_address.addr_type(), address_type);
        assert_eq!(host_address.address(), &address);
    }
}

#[test]
fn encode_decode_host_address_works_fine() {
    let testcases = random_testcases_of_address_type(20, 17);
    for (address_type, address) in testcases {
        let host_address = HostAddress::new(address_type, address.clone());
        let encoded = host_address.to_der();
        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);
        let encoded = encoded.unwrap();
        let decoded = HostAddress::from_der(&encoded);
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);
        let decoded = decoded.unwrap();
        assert_eq!(decoded, host_address);
    }
}

///////////////////////// AuthorizationData //////////////////////////
#[test]
fn ad_entry_should_correctly_identify_its_scope() {
    let testcases: Vec<Scope<ADEntry>> = generate_random_scope_ad(20, 13);
    for scope in testcases {
        let local_use = scope.entry.for_local_use();

        assert!(
            local_use.is_ok(),
            "Failed to get local use: {:?}",
            local_use
        );

        assert_eq!(local_use.unwrap(), scope.for_local);

        let registered_use = scope.entry.for_registered_use();

        assert!(
            registered_use.is_ok(),
            "Failed to get registered use: {:?}",
            registered_use
        );

        assert_eq!(registered_use.unwrap(), !scope.for_local);
    }
}

#[test]
fn ad_entry_encode_decode_works_fine() {
    let testcases: Vec<Scope<ADEntry>> = generate_random_scope_ad(35, 29);
    for scope in testcases {
        let encoded = scope.entry.to_der();

        assert!(encoded.is_ok(), "Failed to encode entry: {:?}", scope.entry);

        let encoded = encoded.unwrap();

        let decoded = ADEntry::from_der(&encoded);

        assert!(decoded.is_ok(), "Failed to decode entry: {:?}", decoded);

        let decoded = decoded.unwrap();

        assert_eq!(decoded, scope.entry);
    }
}

#[test]
fn upgrade_local_ad_entry_should_return_err() {
    let testcases = generate_random_ad_entry(30, 37, |mut r: i32, rng| -> i32 {
        while r == 0 {
            r = rng.gen();
        }
        if r > 0 {
            r = -r;
        }
        r
    });
    for entry in testcases {
        assert!(ADRegisteredEntry::upgrade(&entry).is_err());
    }
}

#[test]
fn encode_decode_if_relevant_works_fine() {
    let entry = mock_ad_if_relevant_data();

    let encoded = entry.to_der().unwrap();

    let decoded = AdIfRelevant::from_der(&encoded);

    assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

    let decoded = decoded.unwrap();

    assert_eq!(
        decoded, entry,
        "Decoded entry is not equal to the original entry"
    );
}

#[test]
fn encode_decode_ad_and_or_works_fine() {
    let entry = mock_ad_and_or_data();

    let encoded = entry.to_der().unwrap();

    let decoded = AdAndOr::from_der(&encoded);

    assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

    let decoded = decoded.unwrap();

    assert_eq!(
        decoded, entry,
        "Decoded entry is not equal to the original entry"
    );
}

#[test]
#[ignore = "This test is ignored because the encoding and decoding of this type is facing some issues in the library itself"]
fn encode_decode_ad_kdc_issued_works_fine() {
    let entries = mock_ad_kdc_issue_data();

    for entry in entries {
        let encoded = entry.to_der().unwrap();

        let decoded = AdKdcIssued::from_der(&encoded);

        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let decoded = decoded.unwrap();

        assert_eq!(
            decoded, entry,
            "Decoded entry is not equal to the original entry"
        );
    }
}

#[test]
fn encode_decode_ad_mandatory_for_kdc_works_fine() {
    let entry = mock_ad_mandatory_for_kdc_data();

    let encoded = entry.to_der().unwrap();

    let decoded = AdMandatoryForKdc::from_der(&encoded);

    assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

    let decoded = decoded.unwrap();

    assert_eq!(
        decoded, entry,
        "Decoded entry is not equal to the original entry"
    );
}

#[test]
#[ignore = "This test is ignored as AdKdcIssued is facing some issues in encoding and decoding in the library itself"]
fn upgrade_registered_ad_entry_should_return_ok_when_given_predefined_code() {
    let testcases = generate_random_ad_entry(45, 47, |_, rng| -> i32 {
        let codes = [1, 4, 5, 8];
        let idx: usize = rng.gen::<usize>() % codes.len();
        codes[idx]
    });
    for entry in testcases {
        let result = ADRegisteredEntry::upgrade(&entry);
        if let Err(err) = result.clone() {
            println!("Error: {:?}", err);
        }
        assert!(result.is_ok());
    }
}

///////////////////////// PaData //////////////////////////
#[test]
fn pa_data_should_correctly_identify_its_scope() {
    let testcases: Vec<Scope<PaData>> = generate_random_scope_pa(20, 13, |r, _| r);
    for scope in testcases {
        let unregistered_use = scope.entry.for_unregistered_use();

        assert!(
            unregistered_use.is_ok(),
            "Failed to get local use: {:?}",
            unregistered_use
        );

        assert_eq!(unregistered_use.unwrap(), scope.for_local);

        let registered_use = scope.entry.for_registered_use();

        assert!(
            registered_use.is_ok(),
            "Failed to get registered use: {:?}",
            registered_use
        );

        assert_eq!(registered_use.unwrap(), !scope.for_local);
    }
}

#[test]
#[ignore = "This test is ignored because the interface of TgsReq is not yet implemented in the library"]
fn encode_decode_for_tgs_req_works_fine() {}

#[test]
fn encode_decode_for_pa_enc_ts_works_fine() {
    let fake_seeds = Faker.fake::<Vec<u64>>();
    for seed in fake_seeds {
        let entry = mock_pa_enc_timestamp(seed as usize);

        let encoded = entry.to_der();

        assert!(encoded.is_ok(), "Failed to encode entry: {:?}", encoded);

        let encoded = encoded.unwrap();

        let decoded = PaEncTimestamp::from_der(&encoded);

        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let decoded = decoded.unwrap();

        assert_eq!(
            decoded, entry,
            "Decoded entry is not equal to the original entry"
        );
    }
}

#[test]
fn encode_decode_for_pa_enc_ts_enc_works_fine() {
    let fake_seeds = Faker.fake::<Vec<u64>>();
    for seed in fake_seeds {
        let entry = mock_pa_enc_ts_enc(seed as usize);

        let encoded = entry.to_der();

        assert!(encoded.is_ok(), "Failed to encode entry: {:?}", encoded);

        let encoded = encoded.unwrap();

        let decoded = PaEncTsEnc::from_der(&encoded);

        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let decoded = decoded.unwrap();

        assert_eq!(
            decoded, entry,
            "Decoded entry is not equal to the original entry"
        );
    }
}

#[test]
#[ignore = "This test is ignored because pw_salt simply masks the octet string"]
fn encode_decode_for_pw_salt_works_fine() {}

#[test]
fn encode_decode_for_etype_info_works_fine() {
    let fake_seeds = Faker.fake::<Vec<u64>>();
    for seed in fake_seeds {
        let entry = mock_etype_info(seed as usize);

        let encoded = entry.to_der();

        assert!(encoded.is_ok(), "Failed to encode entry: {:?}", encoded);

        let encoded = encoded.unwrap();

        let decoded = ETypeInfo::from_der(&encoded);

        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let decoded = decoded.unwrap();

        assert_eq!(
            decoded, entry,
            "Decoded entry is not equal to the original entry"
        );
    }
}

#[test]
fn encode_decode_for_etype_info2_works_fine() {
    let fake_seeds = Faker.fake::<Vec<u64>>();
    for seed in fake_seeds {
        let entry = mock_etype_info2(seed as usize);

        let encoded = entry.to_der();

        assert!(encoded.is_ok(), "Failed to encode entry: {:?}", encoded);

        let encoded = encoded.unwrap();

        let decoded = ETypeInfo2::from_der(&encoded);

        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let decoded = decoded.unwrap();

        assert_eq!(
            decoded, entry,
            "Decoded entry is not equal to the original entry"
        );
    }
}

#[test]
#[ignore = "This test is ignored because the interface of TgsReq is not yet implemented in the library"]
fn upgrade_registered_pa_data_should_return_ok_when_given_predefined_code() {
    let testcases = generate_random_scope_pa(20, 13, |_, rng| -> i32 {
        let codes = [1, 2, 3, 11, 19];
        let idx: usize = rng.gen::<usize>() % codes.len();
        codes[idx]
    });
    for scope in testcases {
        let result = PaDataRegisteredType::upgrade(&scope.entry);
        assert!(result.is_ok());
    }
}

#[test]
fn upgrade_unregistered_pa_data_should_return_err() {
    let testcases: Vec<Scope<PaData>> = generate_random_scope_pa(20, 13, |mut r, rng| {
        while r == 0 {
            r = rng.gen();
        }
        if r > 0 {
            r = -r;
        }
        r
    });

    for scope in testcases {
        assert!(PaDataRegisteredType::upgrade(&scope.entry).is_err());
    }
}

///////////////////////// KerberosFlag //////////////////////////
#[test]
fn kerberos_flags_should_correctly_identify_its_options() {
    let testcases: Vec<(Result<KerberosFlags, &'static str>, &[KerberosFlagsOption])> = vec![
        (
            KerberosFlags::builder().set_proxy().build(),
            &[KerberosFlagsOption::Proxy],
        ),
        (
            KerberosFlags::builder()
                .set_proxy()
                .set_initial()
                .set_postdated()
                .set_forwardable()
                .build(),
            &[
                KerberosFlagsOption::Proxy,
                KerberosFlagsOption::Initial,
                KerberosFlagsOption::Postdated,
                KerberosFlagsOption::Forwardable,
            ],
        ),
        (
            KerberosFlags::builder()
                .set_renewable()
                .set_ok_as_delegate()
                .set_may_postdate()
                .set_transited_policy_checked()
                .build(),
            &[
                KerberosFlagsOption::Renewable,
                KerberosFlagsOption::OkAsDelegate,
                KerberosFlagsOption::MayPostdate,
                KerberosFlagsOption::TransitedPolicyChecked,
            ],
        ),
        (KerberosFlags::builder().build(), &[]),
    ];

    for (flags, options) in testcases {
        assert!(flags.is_ok(), "Failed to build flags: {:?}", flags);

        let flags = flags.unwrap();

        for option in options {
            assert!(flags.is_set(option), "Flag {:?} is not set", option);
        }

        let flags_options = flags.options();

        for option in options {
            assert!(
                flags_options.contains(option),
                "Flag {:?} is not set",
                option
            );
        }
    }
}

#[test]
fn encode_decode_kerberos_flags_works_fine() {
    let testcases: Vec<KerberosFlags> = vec![
        KerberosFlags::builder().set_proxy().build().unwrap(),
        KerberosFlags::builder()
            .set_proxy()
            .set_initial()
            .set_postdated()
            .set_forwardable()
            .build()
            .unwrap(),
        KerberosFlags::builder()
            .set_renewable()
            .set_ok_as_delegate()
            .set_may_postdate()
            .set_transited_policy_checked()
            .build()
            .unwrap(),
        KerberosFlags::builder().build().unwrap(),
    ];

    for flags in testcases {
        let encoded = flags.to_der();

        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let decoded = KerberosFlags::from_der(&encoded.unwrap());

        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let decoded = decoded.unwrap();

        assert_eq!(
            decoded, flags,
            "Decoded flags is not equal to the original flags"
        );
    }
}

///////////////////////// EncryptedData //////////////////////////
#[test]
fn encode_decode_for_encrypted_data_works_fine() {
    let testcases: Vec<EncryptedData> = generate_random_encrypted_data(100, 19);
    for data in testcases {
        let encoded = data.to_der();

        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let decoded = EncryptedData::from_der(&encoded.unwrap());

        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let decoded = decoded.unwrap();

        assert_eq!(
            decoded, data,
            "Decoded data is not equal to the original data"
        );
    }
}

///////////////////////// EncryptionKey //////////////////////////
#[test]
fn encode_decode_for_encryption_key_works_fine() {
    let testcases: Vec<EncryptionKey> = generate_random_encryption_key(100, 19);
    for key in testcases {
        let encoded = key.to_der();

        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let decoded = EncryptionKey::from_der(&encoded.unwrap());

        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let decoded = decoded.unwrap();

        assert_eq!(decoded, key, "Decoded key is not equal to the original key");
    }
}

///////////////////////// Checksum //////////////////////////
#[test]
fn encode_decode_for_checksum_works_fine() {
    let testcases: Vec<Checksum> = generate_random_checksum(100, 19);
    for checksum in testcases {
        let encoded = checksum.to_der();

        assert!(encoded.is_ok(), "Failed to encode: {:?}", encoded);

        let decoded = Checksum::from_der(&encoded.unwrap());

        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded);

        let decoded = decoded.unwrap();

        assert_eq!(
            decoded, checksum,
            "Decoded checksum is not equal to the original checksum"
        );
    }
}
