use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::server::{
    entry::Entry, errors::KrbInfraResult, receiver::AsyncReceiver, ExchangeError, KrbInfraError,
};

pub struct TcpEntry<R: AsyncReceiver + 'static> {
    stream: TcpStream,
    receiver: R,
}

impl<R: AsyncReceiver> TcpEntry<R> {
    pub fn new(stream: TcpStream, receiver: R) -> Self {
        Self { stream, receiver }
    }
}

#[async_trait]
impl<R: AsyncReceiver> Entry for TcpEntry<R> {
    async fn handle(&mut self) -> KrbInfraResult<()> {
        let bytes = {
            // Allocate 4 octets for the length of the message
            let mut buffer = [0u8; 4];

            // Read the length of the message
            self.stream.read_exact(&mut buffer).await?;

            // Convert to u32 and check for the highest bit (this bit must be set to 0 in the current implementation)
            let length = u32::from_be_bytes(buffer);

            if length & 0x80000000 != 0 {
                let response = self
                    .receiver
                    .error(ExchangeError::LengthPrefix { value: length });

                let response = match response {
                    Ok(response) => response,
                    Err(err) => match err {
                        KrbInfraError::Actionable { reply } => reply,
                        KrbInfraError::Aborted { cause: _ } => return Err(err),
                        KrbInfraError::Ignorable => return Ok(()),
                    },
                };

                self.stream.write_all(&response).await?;

                return Ok(());
            }

            // Allocate a buffer of the length of the message and read the message
            let mut buffer = vec![0; length as usize];

            self.stream.read_exact(&mut buffer).await?;

            buffer
        };

        let result = self.receiver.receive(&bytes).await;

        let response = if let Ok(bytes) = result {
            bytes
        } else {
            match result {
                Ok(_) => unreachable!(),
                Err(err) => {
                    if let KrbInfraError::Actionable { reply } = err {
                        reply
                    } else {
                        // Delegate the error to the router
                        return Err(err);
                    }
                }
            }
        };

        self.stream.write_all(&response).await?;

        Ok(())
    }
}
