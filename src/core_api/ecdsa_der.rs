use core::iter;
use der::asn1::UintRef;
use der::{Decode, Reader};

pub struct DerSignature<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

impl<'a> DerSignature<'a> {
    /// Decode the `r` and `s` components of a DER-encoded ECDSA signature.
    ///
    /// Taken from the `ecdsa` crate to avoid bundling the entire dependency.
    pub fn from_der(der_bytes: &'a [u8]) -> der::Result<Self> {
        let mut reader = der::SliceReader::new(der_bytes)?;
        let header = der::Header::decode(&mut reader)?;
        header.tag.assert_eq(der::Tag::Sequence)?;

        let ret = reader.read_nested(header.length, |reader| {
            let r = UintRef::decode(reader)?;
            let s = UintRef::decode(reader)?;
            Ok(DerSignature { r, s })
        })?;

        reader.finish(ret)
    }

    pub fn to_bytes(&self, field_bytes_size: usize) -> impl Iterator<Item = u8> + 'a {
        // Required zero padding
        let r_begin = field_bytes_size.saturating_sub(self.r.as_bytes().len());
        let s_begin = field_bytes_size.saturating_sub(self.s.as_bytes().len());

        iter::repeat_n(0, r_begin)
            .chain(self.r.as_bytes().iter().cloned())
            .chain(iter::repeat_n(0, s_begin))
            .chain(self.s.as_bytes().iter().cloned())
    }
}
