use crate::basic::{Checksum, HostAddress, Int32, OctetString};
use crate::krb_safe_spec::KrbSafe;
use der::{Decode, Encode};

fn minimal_krb_safe() -> KrbSafe {
    KrbSafe::builder()
        .set_user_data(OctetString::new(&[0x0, 0x1, 0x2]).unwrap())
        .set_cksum(Checksum::new(
            Int32::new(&[0x1, 0x2]).unwrap(),
            OctetString::new(&[0x0, 0x1, 0x2]).unwrap(),
        ))
        .set_s_address(
            HostAddress::try_from(
                HostAddress::CODES[0],
                OctetString::new(&[0x0, 0x1, 0x2]).unwrap(),
            )
            .unwrap(),
        )
        .build_unsafe()
}

#[test]
fn encode_then_decode() {
    let msg = minimal_krb_safe();
    let encoded_msg = msg.to_der().unwrap();
    println!("{:x?}", encoded_msg);

    let decoded_msg = KrbSafe::from_der(&encoded_msg).unwrap();

    assert_eq!(msg, decoded_msg);
}
//
// struct SequenceIter<'a> {
//     slice: &'a [u8],
//     current_idx: usize,
// }
//
// impl<'a> SequenceIter<'a> {
//     fn new(slice: &'a [u8]) -> Self {
//         assert_eq!(slice[1] as usize, slice.len() - 1, "Incorrect len for sequence");
//         SequenceIter {
//             slice,
//             current_idx: 2,
//         }
//     }
// }
//
// impl<'a> std::iter::Iterator for SequenceIter<'a> {
//     type Item = &'a [u8];
//
//     fn next(&mut self) -> Option<Self::Item> {
//         let item_start = self.current_idx;
//         let item_end = self.current_idx + self.slice[self.current_idx+1].as
//         let rs = self.slice[self.current_idx..self.slice]
//     }
// }

#[test]
fn correct_encode_header() {
    let msg = minimal_krb_safe();

    let encoded_msg = msg.to_der().unwrap();
    println!("{:?}", encoded_msg);
    assert_eq!(encoded_msg[0], 0b0110_0000 + 20); // APPLICATION  20
    assert_eq!(encoded_msg[2], 0x30); // SEQUENCE

    // pvno
    assert_eq!(encoded_msg[4], 0b1010_0000); // [0] Integer

    // msg-type
    let offset = encoded_msg[5] as usize;
    let next_entry_idx = 5 + offset + 1;
    assert_eq!(encoded_msg[5 + offset + 1], 0b1010_0001);

    let offset = encoded_msg[next_entry_idx + 1] as usize;
    let next_entry_idx = next_entry_idx + 1 + offset + 1;
    assert_eq!(encoded_msg[next_entry_idx], 0b1010_0010);
}
