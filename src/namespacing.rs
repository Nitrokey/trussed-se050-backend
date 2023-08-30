use core::ops::Deref;
use littlefs2::path::Path;
use rand::{CryptoRng, Rng, RngCore};
use se05x::se05x::ObjectId;
use serde::{Deserialize, Serialize};
use trussed::types::KeyId;

use crate::ID_RANGE;

#[derive(Debug, Clone, Copy)]
pub struct FromReprError;

macro_rules! enum_number {
    (
        #[repr($repr:tt)]
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($(#[$doc:meta])* $var:ident = $num:expr),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        #[repr($repr)]
        $vis enum $name {
            $(
                $(#[$doc])*
                $var = $num,
            )*
        }

        impl TryFrom<$repr> for $name {
            type Error = FromReprError;
            fn try_from(val:$repr) -> ::core::result::Result<Self, FromReprError> {
                match val {
                    $(
                        $num => Ok($name::$var),
                    )*
                    _ => Err(FromReprError)
                }
            }
        }

        impl From<$name> for $repr {
            fn from(value: $name) -> $repr {
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

enum_number! {
    #[repr(u8)]
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

enum_number! {
    #[repr(u8)]
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
        #[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
        pub(crate) struct $name(pub(crate) ObjectId);

        impl Deref for $name {
            type Target = ObjectId;
            fn deref(&self) -> &ObjectId {
                &self.0
            }
        }

        impl $name {
            pub fn new<R: RngCore + CryptoRng>(rng: &mut R, ns: NamespaceValue) -> Self {
                Self(generate_object_id_ns(rng, ns, $kind))
            }

            pub fn from_value(mut object: ObjectId) -> Self {
                object.0[3] &= 0xF0;
                object.0[3] |= $kind as u8;
                Self(object)
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

wrapper!(PersistentObjectId, ObjectKind::PersistentKey);
wrapper!(VolatileObjectId, ObjectKind::VolatileKey);
wrapper!(VolatileRsaObjectId, ObjectKind::VolatileRsaKey);
wrapper!(SaltValueObjectId, ObjectKind::VolatileRsaKey);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ParsedObjectId {
    Pin(PinObjectId),
    PersistentKey(PersistentObjectId),
    VolatileKey(VolatileObjectId),
    VolatileRsaKey(VolatileRsaObjectId),
    SaltValue(SaltValueObjectId),
}

impl ParsedObjectId {
    fn parse(id: ObjectId) -> Option<(NamespaceValue, ParsedObjectId)> {
        let (ns, kind) = parse_namespace(id.0[3])?;
        let parsed = match kind {
            ObjectKind::Reserved => return None,
            ObjectKind::PinAesKey | ObjectKind::PinProtectedBinObject => {
                ParsedObjectId::Pin(PinObjectId::from_value(id))
            }
            ObjectKind::PersistentKey => {
                ParsedObjectId::PersistentKey(PersistentObjectId::from_value(id))
            }
            ObjectKind::VolatileKey => {
                ParsedObjectId::VolatileKey(VolatileObjectId::from_value(id))
            }
            ObjectKind::VolatileRsaKey | ObjectKind::VolatileRsaIntermediary => {
                ParsedObjectId::VolatileRsaKey(VolatileRsaObjectId::from_value(id))
            }
            ObjectKind::SaltValue => ParsedObjectId::SaltValue(SaltValueObjectId::from_value(id)),
        };
        Some((ns, parsed))
    }
}

// KEY-ID to ObjectId mapping
// Key IDS are 128 bits
//
// Key IDs that belong to the SE050 backend start with 64 bits of 0xCAFE42424242CAFE to be able to recognize them.
// The next 16 bits are for metadata for the key type
// The next 16 bits are for the privacy of the key public/private
// The next 32 bits are the ObjectId itself
//
// Considerations
//
// The Namespace value within the object ID *MUST* be checked to to be
// - Within the range of acceptable IDs (0x00000000..0x7FFF0000)
// - Within the correct namespace

enum_number! {
    #[repr(u16)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
    pub(crate) enum Privacy {
        Secret = 0x0,
        Public = 0x1,
    }
}

enum_number! {
    #[repr(u16)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
    pub(crate) enum KeyType {
        Ed255 = 0x0,
        X255 = 0x1,
        P256 = 0x2,
        Rsa2048 = 0x4,
        Rsa3072 = 0x5,
        Rsa4096 = 0x6,
    }
}

pub(crate) fn key_id_for_obj(obj: ObjectId, privacy: Privacy, ty: KeyType) -> KeyId {
    let mut base = 0xCAFE42424242CAFE0000000000000000;
    let obj = u32::from_be_bytes(obj.0);
    base |= obj as u128;
    base |= (privacy as u16 as u128) << 32;
    base |= (ty as u16 as u128) << (32 + 16);

    KeyId::from_value(base)
}

pub(crate) fn parse_key_id(
    id: KeyId,
    ns: NamespaceValue,
) -> Option<(ParsedObjectId, KeyType, Privacy)> {
    let val = id.value();
    if val & 0xFFFFFFFFFFFFFFFF0000000000000000 != 0xCAFE42424242CAFE0000000000000000 {
        return None;
    }

    let ty = (((val & 0xFFFF << (32 + 16)) >> (32 + 16)) as u16)
        .try_into()
        .ok()?;
    let privacy = (((val & 0xFFFF << 32) >> 32) as u16).try_into().ok()?;

    let id_value = val as u32;
    if !ID_RANGE.contains(&id_value) {
        return None;
    }
    let (parsed_ns, parsed_id) = ParsedObjectId::parse(ObjectId(id_value.to_be_bytes()))?;

    // IMPORTANT! Don't all applications to access other applications' keys
    if parsed_ns != ns {
        return None;
    }
    Some((parsed_id, ty, privacy))
}

#[cfg(test)]
mod tests2 {
    use super::*;
    #[test]
    fn key_ids() {
        let obj_id = PinObjectId::from_value(ObjectId(0x0ABBCCDDu32.to_be_bytes()));
        assert!(ID_RANGE.contains(&u32::from_be_bytes(obj_id.0 .0)));
        assert_eq!(
            KeyId::from_value(0xCAFE42424242CAFE000400010ABBCCD1u128),
            key_id_for_obj(*obj_id, Privacy::Public, KeyType::Rsa2048)
        );

        let ns = 0xD.try_into().unwrap();
        for ty in KeyType::all() {
            for p in Privacy::all() {
                let key_id = key_id_for_obj(*obj_id, *p, *ty);
                let (parsed_key, parsed_ty, parsed_priv) = parse_key_id(key_id, ns).unwrap();
                assert_eq!(parsed_key, ParsedObjectId::Pin(obj_id));
                assert_eq!(parsed_ty, *ty);
                assert_eq!(parsed_priv, *p)
            }
        }
    }
}
