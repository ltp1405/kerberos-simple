use crate::cryptography::Cryptography;
use messages::basic_types::{Int32, PrincipalName, SequenceOf};
use messages::{AsRep, AsReq, Ecode, KrbErrorMsg};

pub trait PrincipalDatabase {
    fn get_client_principal_key(&self, principal_name: &PrincipalName) -> Option<String>;
    fn get_server_principal_key(&self, principal_name: &PrincipalName) -> Option<String>;
}
#[derive(Debug)]
enum ServerError {
    ProtocolError(KrbErrorMsg),
    Internal,
    CannotDecode,
}

struct AuthenticationService<'a, P, C>
where
    P: PrincipalDatabase,
    C: Cryptography,
{
    require_pre_authenticate: bool,
    principal_db: &'a P,
    crypto: &'a C,
}

type Result<T> = std::result::Result<T, ServerError>;

impl<'a, P, C> AuthenticationService<'a, P, C>
where
    P: PrincipalDatabase,
    C: Cryptography,
{
    fn handle_krb_as_req(&self, as_req: &AsReq) -> Result<AsRep> {
        let mut error_msg = self.default_error_builder();
        self.principal_db.get_client_principal_key(
            as_req.req_body().cname().ok_or(ServerError::ProtocolError(
                error_msg
                    .error_code(Ecode::KDC_ERR_C_PRINCIPAL_UNKNOWN)
                    .build()
                    .unwrap(),
            ))?,
        );

        self.principal_db.get_server_principal_key(
            as_req.req_body().cname().ok_or(ServerError::ProtocolError(
                error_msg
                    .error_code(Ecode::KDC_ERR_S_PRINCIPAL_UNKNOWN)
                    .build()
                    .unwrap(),
            ))?,
        );

        if self.require_pre_authenticate {
            todo!("Pre-auth is not yet implemented")
        }
        self.verify_encryption_type(as_req)?;

        let ss_key = self
            .crypto
            .generate_key()
            .map_err(|_| ServerError::Internal);

        let selected_client_key = self.get_suitable_encryption_key(as_req.req_body().etype())?;

        todo!()
    }

    fn verify_encryption_type(&self, as_req: &AsReq) -> Result<()> {
        Ok(())
    }

    fn get_suitable_encryption_key(
        &self,
        etype: &SequenceOf<Int32>,
    ) -> Result<Vec<u8>> {
        todo!()
    }
}
