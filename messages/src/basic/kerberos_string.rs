use der::asn1::Ia5String;
use der::{DecodeValue, EncodeValue, Header, Length, Reader, Sequence, Writer};

/// Ia5String
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct KerberosString(Ia5String);

impl EncodeValue for KerberosString {
    fn value_len(&self) -> der::Result<Length> {
        self.0.value_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode_value(encoder)
    }
}

impl<'a> DecodeValue<'a> for KerberosString {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        Ok(KerberosString(Ia5String::decode_value(reader, header)?))
    }
}

impl<'a> Sequence<'a> for KerberosString {}

impl TryFrom<String> for KerberosString {
    type Error = der::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(KerberosString(Ia5String::try_from(value)?))
    }
}
