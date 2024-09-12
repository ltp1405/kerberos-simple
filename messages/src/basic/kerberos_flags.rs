use crate::basic::BitString;
use der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Writer};

// RFC4120 5.2.8
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct KerberosFlags {
    inner: BitString,
}

impl KerberosFlags {
    pub fn builder() -> KerberosFlagsBuilder {
        KerberosFlagsBuilder::new()
    }

    pub fn is_set(&self, bit_pos: usize) -> bool {
        let bit = (bit_pos % 8) as u8;
        let shift = 7 - bit;
        let idx = bit_pos / 8;
        let bytes = self.inner.raw_bytes();
        bytes
            .get(idx)
            .map_or(false, |byte| byte & (1 << shift) != 0)
    }
}

impl FixedTag for KerberosFlags {
    const TAG: der::Tag = der::Tag::BitString;
}

impl EncodeValue for KerberosFlags {
    fn value_len(&self) -> der::Result<Length> {
        self.inner.value_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.inner.encode_value(encoder)
    }
}

impl<'a> DecodeValue<'a> for KerberosFlags {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let inner = BitString::decode_value(reader, header)?;
        Ok(Self { inner })
    }
}

pub struct KerberosFlagsBuilder {
    inner: Vec<u8>,
}

impl KerberosFlagsBuilder {
    fn new() -> Self {
        Self {
            inner: Vec::from([0u8; 4]),
        }
    }

    pub fn set(&mut self, bit_pos: usize) -> &mut Self {
        if bit_pos >= 32 {
            self.inner.resize(bit_pos / 8 + 1, 0);
        }
        let bit = (bit_pos % 8) as u8;
        let shift = 7 - bit;
        let idx = bit_pos / 8;
        self.inner[idx] |= 1 << shift;
        self
    }

    pub fn build(&mut self) -> Result<KerberosFlags, &'static str> {
        let inner = BitString::new(0, self.inner.clone()).map_err(|_| "Invalid bit string")?;
        Ok(KerberosFlags { inner })
    }
}