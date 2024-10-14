use core::ops::Deref;
use littlefs2_core::Path;
use rand::{CryptoRng, Rng, RngCore};
use se05x::se05x::ObjectId;
use serde::{Deserialize, Serialize};
use trussed::{key::Kind, types::KeyId};

use crate::ID_RANGE;

#[derive(Debug, Clone, Copy)]
pub struct FromReprError;

macro_rules! enum_number {
    (
        #[repr($repr:tt)]
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($(#[cfg($cfg:meta)])* $(#[doc = $doc:literal])* $var:ident = $num:expr),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        #[repr($repr)]
        $vis enum $name {
            $(
                $(#[cfg($cfg)])*
                $(#[doc = $doc])*
                $var = $num,
            )*
        }

        impl TryFrom<$repr> for $name {
            type Error = FromReprError;
            fn try_from(val:$repr) -> ::core::result::Result<Self, FromReprError> {
                match val {
                    $(
                        $(#[cfg($cfg)])*
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
                        $(#[cfg($cfg)])*
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
                        $(#[cfg($cfg)])*
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
        /// The AES authentication object that is used to verify PINS for a PIN that has an associated AES key
        PinAesKeyWithDerived = 0x2,
        /// The BinaryObject that is read-protected by the PIN of same ID but PinAesKey type
        PinProtectedBinObject = 0x3,
        /// A persistent key
        PersistentKey = 0x4,
        /// A volatile key. The private key data is cleared unless the key is currently in use
        VolatileKey = 0x5,
        /// A "volatile" RSA key. Since RSA keys are too large to fit in the SE050 volatile memory, they are auctally stored in persistent storage, and protected by a AES authentication object
        VolatileRsaKey = 0x6,
        /// The AES authentication object that protects the Volatile RSA key of same id.
        VolatileRsaIntermediary = 0x7,
        /// Temporary public key being loaded into the SE050 for 1 operation. Must be deleted just after
        PublicTemporary = 0x8,
        /// Salt value  stored on the SE050
        SaltValue = 0xF,
    }
}

macro_rules! enum_from {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($(#[$doc:meta])* $var:ident($ty:tt)),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        $vis enum $name {
            $(
                $(#[$doc])*
                $var($ty),
            )*
        }

        $(
            impl From<$ty> for $name {
                fn from(value: $ty) -> $name {
                    $name::$var(value)
                }
            }
        )*
    };
}

/// A namespace Item
pub struct NamespaceItem {
    pub client: &'static Path,
    pub value: NamespaceValue,
}

/// A namespace.
pub struct Namespace(pub &'static [NamespaceItem]);

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
            0x85
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

        #[allow(unused)]
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

pub(crate) fn generate_object_id_ns<R: RngCore + CryptoRng>(
    rng: &mut R,
    ns: NamespaceValue,
    kind: ObjectKind,
) -> ObjectId {
    let mut base = rng.gen_range(0x00000000u32..0x7FFF0000).to_be_bytes();
    base[3] = namespace(ns, kind);
    ObjectId(base)
}

wrapper!(PinObjectId, ObjectKind::PinAesKey);
wrapper!(PinObjectIdWithDerived, ObjectKind::PinAesKeyWithDerived);

impl PinObjectIdWithDerived {
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

impl VolatileRsaObjectId {
    pub(crate) fn key_id(&self) -> ObjectId {
        self.0
    }

    pub(crate) fn intermediary_key_id(&self) -> ObjectId {
        let mut base = self.0 .0;
        base[3] += 1;
        assert_eq!(
            parse_namespace(base[3]).unwrap().1,
            ObjectKind::VolatileRsaIntermediary
        );
        ObjectId(base)
    }
}

wrapper!(SaltValueObjectId, ObjectKind::VolatileRsaKey);

enum_from!(
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum ParsedObjectId {
        Pin(PinObjectId),
        PinWithDerived(PinObjectIdWithDerived),
        PersistentKey(PersistentObjectId),
        VolatileKey(VolatileObjectId),
        VolatileRsaKey(VolatileRsaObjectId),
        SaltValue(SaltValueObjectId),
    }
);

impl ParsedObjectId {
    pub(crate) fn parse(id: ObjectId) -> Option<(NamespaceValue, ParsedObjectId)> {
        let (ns, kind) = parse_namespace(id.0[3])?;
        let parsed = match kind {
            ObjectKind::Reserved => return None,
            ObjectKind::PinAesKey => PinObjectIdWithDerived::from_value(id).into(),
            ObjectKind::PinAesKeyWithDerived | ObjectKind::PinProtectedBinObject => {
                PinObjectIdWithDerived::from_value(id).into()
            }
            ObjectKind::PersistentKey => PersistentObjectId::from_value(id).into(),
            ObjectKind::VolatileKey => VolatileObjectId::from_value(id).into(),
            ObjectKind::VolatileRsaKey | ObjectKind::VolatileRsaIntermediary => {
                VolatileRsaObjectId::from_value(id).into()
            }
            ObjectKind::SaltValue => SaltValueObjectId::from_value(id).into(),
            ObjectKind::PublicTemporary => return None,
        };
        Some((ns, parsed))
    }
}

// KEY-ID to ObjectId mapping
// Key IDS are 128 bits
//
// Key IDs that belong to the SE050 backend start with 64 bits of 0xCAFE42424242CAFE to be able to recognize them.
// The next 16 bits are for metadata for the key type
// The next 16 bits are RFU
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
        P384 = 0x7,
        P521 = 0x8,
        BrainpoolP256R1 = 0x9,
        BrainpoolP384R1 = 0xA,
        BrainpoolP512R1 = 0xB,
    }
}

impl KeyType {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Ed255 => Kind::Ed255,
            Self::X255 => Kind::X255,
            Self::P256 => Kind::P256,
            Self::P384 => Kind::P384,
            Self::P521 => Kind::P521,
            Self::BrainpoolP256R1 => Kind::BrainpoolP256R1,
            Self::BrainpoolP384R1 => Kind::BrainpoolP384R1,
            Self::BrainpoolP512R1 => Kind::BrainpoolP512R1,
            Self::Rsa2048 => Kind::Rsa2048,
            Self::Rsa3072 => Kind::Rsa3072,
            Self::Rsa4096 => Kind::Rsa4096,
        }
    }
}

const TY_OFFSET: u32 = 32;

pub(crate) fn key_id_for_obj(obj: ObjectId, ty: KeyType) -> KeyId {
    let mut base = 0xCAFE42424242CAFE0000000000000000;
    let obj = u32::from_be_bytes(obj.0);
    base |= obj as u128;
    base |= (ty as u16 as u128) << TY_OFFSET;

    KeyId::from_value(base)
}

pub(crate) fn parse_key_id(id: KeyId, ns: NamespaceValue) -> Option<(ParsedObjectId, KeyType)> {
    let val = id.value();
    if val & 0xFFFFFFFFFFFFFFFF0000000000000000 != 0xCAFE42424242CAFE0000000000000000 {
        return None;
    }

    let ty = (((val & 0xFFFF << TY_OFFSET) >> TY_OFFSET) as u16)
        .try_into()
        .ok()?;

    let id_value = val as u32;
    if !ID_RANGE.contains(&id_value) {
        return None;
    }
    let (parsed_ns, parsed_id) = ParsedObjectId::parse(ObjectId(id_value.to_be_bytes()))?;

    // IMPORTANT! Don't all applications to access other applications' keys
    if parsed_ns != ns {
        return None;
    }
    Some((parsed_id, ty))
}

#[cfg(test)]
mod tests2 {
    use super::*;
    #[test]
    fn key_ids() {
        let obj_id = PinObjectIdWithDerived::from_value(ObjectId(0x0ABBCCDDu32.to_be_bytes()));
        assert!(ID_RANGE.contains(&u32::from_be_bytes(obj_id.0 .0)));
        assert_eq!(
            KeyId::from_value(0xCAFE42424242CAFE000000040ABBCCD2u128),
            key_id_for_obj(*obj_id, KeyType::Rsa2048)
        );

        let ns = 0xD.try_into().unwrap();
        for ty in KeyType::all() {
            let key_id = key_id_for_obj(*obj_id, *ty);
            let (parsed_key, parsed_ty) = parse_key_id(key_id, ns).unwrap();
            assert_eq!(parsed_key, ParsedObjectId::PinWithDerived(obj_id));
            assert_eq!(parsed_ty, *ty);
        }
    }
}
