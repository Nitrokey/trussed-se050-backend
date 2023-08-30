use core::ops::Deref;
use littlefs2::path::Path;
use rand::{CryptoRng, Rng, RngCore};
use se05x::se05x::ObjectId;
use serde::{Deserialize, Serialize};

pub struct FromU8Error;

macro_rules! enum_u8 {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($(#[$doc:meta])* $var:ident = $num:expr),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        #[repr(u8)]
        $vis enum $name {
            $(
                $(#[$doc])*
                $var = $num,
            )*
        }

        impl TryFrom<u8> for $name {
            type Error = FromU8Error;
            fn try_from(val: u8) -> ::core::result::Result<Self, FromU8Error> {
                match val {
                    $(
                        $num => Ok($name::$var),
                    )*
                    _ => Err(FromU8Error)
                }
            }
        }

        impl From<$name> for u8 {
            fn from(value: $name) -> u8 {
                match value {
                    $(
                        $name::$var => $num,
                    )*
                }

            }
        }

        impl $name {
            #[allow(unused)]
            pub const fn all() -> &'static [$name] {
                &[
                    $(
                        $name::$var
                    ),*
                ]
            }
        }
    }
}

enum_u8! {
    /// 4 bits that represent which client does the object belongs to
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
    pub enum NamespaceValue {
        Client0 = 0x0,
        Client1 = 0x1,
        Client2 = 0x2,
        Client3 = 0x3,
        Client4 = 0x4,
        Client5 = 0x5,
        Client6 = 0x6,
        Client7 = 0x7,
        Client8 = 0x8,
        Client9 = 0x9,
        ClientA = 0xA,
        ClientB = 0xB,
        ClientC = 0xC,
        ClientD = 0xD,
        ClientE = 0xE,
        NoClient = 0xF,
    }
}

enum_u8! {
    /// 4 bits representing the kind of an object
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
    pub(crate) enum ObjectKind {
        /// Reserved for future use, to indicate more namespacing
        Reserved = 0x0,
        /// The AES authentication object that is used to verify PINS
        PinAesKey = 0x1,
        /// The BinaryObject that is read-protected by the PIN of same ID but PinAesKey type
        PinProtectedBinObject = 0x2,
        /// A persistent key
        PersistentKey = 0x3,
        /// A volatile key. The private key data is cleared unless the key is currently in use
        VolatileKey = 0x4,
        /// A "volatile" RSA key. Since RSA keys are too large to fit in the SE050 volatile memory, they are auctally stored in persistent storage, and protected by a AES authentication object
        VolatileRsaKey = 0x5,
        /// The AES authentication object that protects the Volatile RSA key of same id.
        VolatileRsaIntermediary = 0x6,
        /// Salt value  stored on the SE050
        SaltValue = 0xF,
    }
}

/// A namespace Item
pub struct NamespaceItem {
    pub client: &'static Path,
    pub value: NamespaceValue,
}

/// A namespace.
pub struct Namespace(&'static [NamespaceItem]);

impl Namespace {
    pub fn for_client(&self, client_id: &Path) -> Option<NamespaceValue> {
        for item in self.0 {
            if item.client == client_id {
                return Some(item.value);
            }
        }
        None
    }
}

pub(crate) const fn namespace(client: NamespaceValue, kind: ObjectKind) -> u8 {
    let msb = client as u8;
    let lsb = kind as u8;

    (msb << 4) | lsb
}

pub(crate) fn parse_namespace(ns: u8) -> Option<(NamespaceValue, ObjectKind)> {
    let msb = (ns & 0xF0) >> 4;
    let lsb = ns & 0xF;

    let msb_parsed = msb.try_into().ok();
    let lsb_parsed = lsb.try_into().ok();
    msb_parsed.zip(lsb_parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_byte() {
        assert_eq!(
            namespace(NamespaceValue::Client8, ObjectKind::VolatileKey),
            0x84
        );

        for ns in NamespaceValue::all() {
            for kind in ObjectKind::all() {
                let byte = namespace(*ns, *kind);
                let (parsed_ns, parsed_kind) = parse_namespace(byte).unwrap();
                assert_eq!(*ns, parsed_ns);
                assert_eq!(*kind, parsed_kind);
            }
        }
    }
}

macro_rules! wrapper {
    ($name:ident, $kind:expr) => {
        #[derive(Debug, Clone, Copy, Deserialize, Serialize)]
        pub(crate) struct $name(pub(crate) ObjectId);

        impl $name {
            pub fn new<R: RngCore + CryptoRng>(rng: &mut R, ns: NamespaceValue) -> Self {
                Self(generate_object_id_ns(rng, ns, $kind))
            }
        }
    };
}

fn generate_object_id_ns<R: RngCore + CryptoRng>(
    rng: &mut R,
    ns: NamespaceValue,
    kind: ObjectKind,
) -> ObjectId {
    let mut base = rng.gen_range(0x00000000u32..0x7FFF0000).to_be_bytes();
    base[3] = namespace(ns, kind);
    ObjectId(base)
}

wrapper!(PinObjectId, ObjectKind::PinAesKey);

impl PinObjectId {
    pub(crate) fn pin_id(&self) -> ObjectId {
        self.0
    }

    pub(crate) fn protected_key_id(&self) -> ObjectId {
        let mut base = self.0 .0;
        base[3] += 1;
        assert_eq!(
            parse_namespace(base[3]).unwrap().1,
            ObjectKind::PinProtectedBinObject
        );
        ObjectId(base)
    }
}
