use der::asn1::Ia5String;
use der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag, Writer};

/// Ia5String
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct KerberosString(Ia5String);

impl FixedTag for KerberosString {
    const TAG: Tag = Tag::Ia5String;
}

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

impl KerberosString {
    pub fn new<T>(input: &T) -> Result<Self, der::Error>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Ok(KerberosString(Ia5String::new(input)?))
    }
}

impl TryFrom<String> for KerberosString {
    type Error = der::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(KerberosString(Ia5String::try_from(value)?))
    }
}

impl TryFrom<&'static str> for KerberosString {
    type Error = der::Error;

    fn try_from(value: &'static str) -> Result<Self, Self::Error> {
        Ok(KerberosString(Ia5String::try_from(value.to_string())?))
    }
}
