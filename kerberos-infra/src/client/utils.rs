use tokio::{io::AsyncReadExt, net::TcpStream};

use super::KrbInfraCltErr;

pub(super) struct TagLengthStreamReader<'a, 'b> {
    stream: &'a mut &'b mut TcpStream,
    inner_buffer: Vec<u8>,
}

impl<'a, 'b> TagLengthStreamReader<'a, 'b> {
    // Try to read from the stream, records the bytes read
    // and handle the logic of long and short messages
    // Returns the buffer for the incoming message and the so-far read bytes
    pub async fn try_into(mut self) -> Result<(Vec<u8>, Vec<u8>), KrbInfraCltErr> {
        // Read the tag and length bytes
        self.read_and_record_next(2).await?;

        let is_long_msg = self.get_len_byte() & 0x80 == 0x80;

        let expected_buffer_len = if is_long_msg {
            let total_chunks = (self.get_len_byte() & 0x7F) as usize;
            self.read_and_record_next(total_chunks).await?;
            let len_bytes = self.inner_buffer[2..2 + total_chunks].to_vec();
            let length = len_bytes.iter().fold(0, |acc, &x| acc * 256 + x as usize);
            length
        } else {
            (self.get_len_byte() & 0x7F) as usize
        };

        Ok((vec![0u8; expected_buffer_len], self.inner_buffer))
    }

    async fn read_and_record_next(&mut self, len: usize) -> Result<(), KrbInfraCltErr> {
        let mut buffer = vec![0u8; len];
        self.stream.read_exact(&mut buffer).await?;
        self.inner_buffer.extend_from_slice(&buffer);
        Ok(())
    }

    fn get_len_byte(&self) -> u8 {
        self.inner_buffer[1]
    }
}

impl<'a, 'b> From<&'a mut &'b mut TcpStream> for TagLengthStreamReader<'a, 'b>
where
    'b: 'a,
{
    fn from(stream: &'a mut &'b mut TcpStream) -> Self {
        Self {
            stream,
            inner_buffer: vec![],
        }
    }
}
