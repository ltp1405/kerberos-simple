use std::net::SocketAddr;

use tokio::{io::AsyncReadExt, net::TcpStream};

use super::HostError;

pub fn handle_result_at_router(addr: SocketAddr, result: Result<(), HostError>) {
    println!("Connection from {} closed", addr);
    match result {
        Ok(_) => {}
        Err(err) => {
            if let HostError::Aborted { cause } = err {
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
    result: Result<Vec<u8>, HostError>,
) -> Result<Vec<u8>, HostError> {
    match result {
        Ok(bytes) => Ok(bytes),
        Err(err) => match err {
            HostError::Actionable { reply } => Ok(reply),
            _ => Err(err),
        },
    }
}

pub(super) struct TagLengthStreamReader<'a> {
    stream: &'a mut TcpStream,
    inner_buffer: Vec<u8>,
}

impl<'a> TagLengthStreamReader<'a> {
    // Try to read from the stream, records the bytes read
    // and handle the logic of long and short messages
    // Returns the buffer for the incoming message and the so-far read bytes
    pub async fn try_into(mut self) -> Result<(Vec<u8>, Vec<u8>), HostError> {
        // Read the tag and length bytes
        self.read_next(2).await?;

        let is_long_msg = self.get_len_byte() & 0x80 == 0x80;

        let expected_buffer_len = if is_long_msg {
            let total_chunks = (self.get_len_byte() & 0x7F) as usize;
            self.read_next(total_chunks).await?;
            let len_bytes = self.inner_buffer[2..2 + total_chunks].to_vec();
            let length = len_bytes.iter().fold(0, |acc, &x| acc * 256 + x as usize);
            length
        } else {
            (self.get_len_byte() & 0x7F) as usize
        };

        Ok((vec![0u8; expected_buffer_len], self.inner_buffer))
    }

    async fn read_next(&mut self, len: usize) -> Result<(), HostError> {
        let mut buffer = vec![0u8; len];
        self.stream.read_exact(&mut buffer).await?;
        self.inner_buffer.extend_from_slice(&buffer);
        Ok(())
    }

    fn get_len_byte(&self) -> u8 {
        self.inner_buffer[1]
    }
}

impl<'a> From<&'a mut TcpStream> for TagLengthStreamReader<'a> {
    fn from(stream: &'a mut TcpStream) -> Self {
        Self {
            stream,
            inner_buffer: vec![],
        }
    }
}
