use messages::basic_types::{PrincipalName, Realm};

pub struct AuthenticationServiceConfig {
    pub realm: Realm,
    pub sname: PrincipalName,
    pub require_preauth: bool,
}

impl AuthenticationServiceConfig {
    #[cfg(test)]
    pub fn local(require_preauth: bool) -> Self {
        use messages::basic_types::{KerberosString, NameTypes};

        let realm = Realm::try_from("EXAMPLE.COM").unwrap();

        let sname = PrincipalName::new(
            NameTypes::NtEnterprise,
            vec![KerberosString::try_from("host").unwrap()],
        )
        .unwrap();

        Self {
            realm,
            sname,
            require_preauth,
        }
    }
}

pub struct TicketGrantingServiceConfig {
    pub realm: Realm,
    pub sname: PrincipalName,
}

impl TicketGrantingServiceConfig {
    #[cfg(test)]
    pub fn local() -> Self {
        use messages::basic_types::{KerberosString, NameTypes};

        let realm = Realm::try_from("EXAMPLE.COM").unwrap();

        let sname = PrincipalName::new(
            NameTypes::NtEnterprise,
            vec![KerberosString::try_from("host").unwrap()],
        )
        .unwrap();

        Self { realm, sname }
    }
}
