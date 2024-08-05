use std::net::TcpStream;

pub struct TGS {}

impl TGS {
    
    pub async fn respond_with_tgt(&self, mut client: TcpStream) -> tokio::io::Result<Vec<u8>> {
        todo!();
    }
}