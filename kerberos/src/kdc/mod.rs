pub struct KDC {}

impl KDC {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn authenticate_client(&mut self, principal_name: &str) -> tokio::io::Result<Vec<u8>> {
        todo!();
    }
    pub async fn send_ticket(&mut self, principal_name: &str, ticket: Vec<u8>) ->  tokio::io::Result<Vec<u8>>{
        todo!();
    }
    pub async fn return_tgt(&mut self, principal_name: &str) -> tokio::io::Result<Vec<u8>>{
        todo!();
    }
    pub async fn return_service_ticket(&mut self, principal_name: &str) -> tokio::io::Result<Vec<u8>> {
        todo!();
    }
    pub async fn return_session_key(&mut self, principal_name: &str) -> tokio::io::Result<Vec<u8>>{
        todo!();
    } 
}