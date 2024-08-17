use std::net::SocketAddr;

use super::KrbInfraError;

pub fn handle_result_at_router(addr: SocketAddr, result: Result<(), KrbInfraError>) {
    match result {
        Ok(_) => {}
        Err(err) => {
            if let KrbInfraError::Aborted { cause } = err {
                match cause {
                    Some(inner) => {
                        eprintln!("Connection from {} aborted: {}", addr, inner)
                    }
                    None => {
                        eprintln!("Connection from {} aborted for no reason", addr)
                    }
                }
            }
        }
    }
}

pub fn extract_bytes_or_delegate_to_router(
    result: Result<Vec<u8>, KrbInfraError>,
) -> Result<Vec<u8>, KrbInfraError> {
    match result {
        Ok(bytes) => Ok(bytes),
        Err(err) => match err {
            KrbInfraError::Actionable { reply } => Ok(reply),
            _ => Err(err),
        },
    }
}
