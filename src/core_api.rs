//! Implementations of the core APIs for the SE050 backend

use cbor_smol::{cbor_deserialize, cbor_serialize};
use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use littlefs2::path::PathBuf;
use rand::{CryptoRng, RngCore};
use se05x::{
    se05x::{
        commands::{
            CheckObjectExists, CloseSession, CreateSession, DeleteSecureObject,
            EcdhGenerateSharedSecret, ExportObject, GetRandom, ImportObject, ReadObject,
            RsaDecrypt, VerifySessionUserId, WriteEcKey, WriteRsaKey, WriteSymmKey, WriteUserId,
        },
        policies::{ObjectAccessRule, ObjectPolicyFlags, Policy, PolicySet},
        EcCurve, ObjectId, P1KeyType, RsaEncryptionAlgo, Se05XResult, SymmKeyType,
    },
    t1::I2CForT1,
};
use serde::{Deserialize, Serialize};
use trussed::{
    api::{reply, request, Request},
    backend::Backend,
    config::MAX_MESSAGE_LENGTH,
    key::{self, Kind, Secrecy},
    service::Keystore,
    types::{KeyId, Location, Mechanism, Message, Vec},
    Bytes, Error,
};

use crate::{
    namespacing::{
        key_id_for_obj, parse_key_id, KeyType, NamespaceValue, ParsedObjectId, PersistentObjectId,
        Privacy, VolatileObjectId, VolatileRsaObjectId,
    },
    Context, Se050Backend, BACKEND_DIR,
};

const BUFFER_LEN: usize = 2048;
const CORE_DIR: &str = "se050-core";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum PersistentMaterial {
    Persistent(PersistentObjectId),
    Volatile(VolatileObjectId),
    VolatileRsa(VolatileRsaObjectId),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VolatileKeyMaterial {
    object_id: VolatileObjectId,
    persistent_metadata: KeyId,
    exported_material: Bytes<1024>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VolatileKeyMaterialRef<'a> {
    object_id: VolatileObjectId,
    #[serde(serialize_with = "serde_bytes::serialize")]
    exported_material: &'a [u8],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VolatileRsaKey {
    key_id: VolatileRsaObjectId,
    #[serde(with = "serde_byte_array")]
    intermediary_key: [u8; 16],
}

/// The bool returned points at wether the mechanism is raw RSA
fn bits_and_kind_from_mechanism(mechanism: Mechanism) -> Result<(usize, key::Kind, bool), Error> {
    match mechanism {
        Mechanism::Rsa2048Pkcs1v15 => Ok((2048, key::Kind::Rsa2048, false)),
        Mechanism::Rsa3072Pkcs1v15 => Ok((3072, key::Kind::Rsa3072, false)),
        Mechanism::Rsa4096Pkcs1v15 => Ok((4096, key::Kind::Rsa4096, false)),
        Mechanism::Rsa2048Raw => Ok((2048, key::Kind::Rsa2048, true)),
        Mechanism::Rsa3072Raw => Ok((3072, key::Kind::Rsa3072, true)),
        Mechanism::Rsa4096Raw => Ok((4096, key::Kind::Rsa4096, true)),
        _ => Err(Error::RequestNotAvailable),
    }
}

impl<Twi: I2CForT1, D: DelayUs<u32>> Se050Backend<Twi, D> {
    fn random_bytes(&mut self, count: usize) -> Result<trussed::Reply, Error> {
        if count >= MAX_MESSAGE_LENGTH {
            return Err(Error::MechanismParamInvalid);
        }

        let mut buf = [0; BUFFER_LEN];
        let res = self
            .se
            .run_command(
                &GetRandom {
                    length: (count as u16).into(),
                },
                &mut buf,
            )
            .map_err(|_err| {
                error!("Failed to get random: {:?}", _err);
                Error::FunctionFailed
            })?;
        if res.data.len() != count {
            error!("Bad random length");
            return Err(Error::FunctionFailed);
        }
        Ok(reply::RandomBytes {
            bytes: Message::from_slice(res.data).unwrap(),
        }
        .into())
    }

    fn delete(
        &mut self,
        key: &KeyId,
        ns: NamespaceValue,
        keystore: &mut impl Keystore,
    ) -> Result<reply::Delete, Error> {
        let (parsed_key, _parsed_ty) = parse_key_id(*key, ns).ok_or_else(|| {
            debug_now!("Failed to parse key id");
            Error::RequestNotAvailable
        })?;
        match parsed_key {
            ParsedObjectId::Pin(_)
            | ParsedObjectId::PinWithDerived(_)
            | ParsedObjectId::SaltValue(_) => return Err(Error::ObjectHandleInvalid),
            ParsedObjectId::PersistentKey(PersistentObjectId(obj)) => {
                self.delete_persistent_key(obj)
            }
            ParsedObjectId::VolatileKey(VolatileObjectId(obj)) => {
                self.delete_volatile_key(&key, obj, keystore)
            }
            ParsedObjectId::VolatileRsaKey(obj) => {
                self.delete_volatile_rsa_key(*key, obj, keystore)
            }
        }
    }

    fn delete_persistent_key(&mut self, object_id: ObjectId) -> Result<reply::Delete, Error> {
        let buf = &mut [0; 1024];
        self.se
            .run_command(&DeleteSecureObject { object_id }, buf)
            .map_err(|_err| {
                debug_now!("Failed to delete key: {_err:?}");
                Error::FunctionFailed
            })?;
        Ok(reply::Delete { success: true })
    }

    fn delete_volatile_key(
        &mut self,
        key: &KeyId,
        object_id: ObjectId,
        keystore: &mut impl Keystore,
    ) -> Result<reply::Delete, Error> {
        let buf = &mut [0; 1024];
        self.se
            .run_command(&DeleteSecureObject { object_id }, buf)
            .or(Err(Error::FunctionFailed))?;
        Ok(reply::Delete {
            success: keystore.delete_key(key),
        })
    }

    fn delete_volatile_rsa_key(
        &mut self,
        key: KeyId,
        se_id: VolatileRsaObjectId,
        keystore: &mut impl Keystore,
    ) -> Result<reply::Delete, Error> {
        let buf = &mut [0; 1024];

        let exists = self
            .se
            .run_command(
                &CheckObjectExists {
                    object_id: se_id.key_id(),
                },
                buf,
            )
            .map_err(|_err| {
                debug!("Failed existence check: {_err:?}");
                Error::FunctionFailed
            })?
            .result;
        if exists == Se05XResult::Success {
            debug!("Deleting key");
            self.se
                .run_command(
                    &DeleteSecureObject {
                        object_id: se_id.key_id(),
                    },
                    buf,
                )
                .map_err(|_err| {
                    debug!("Failed deletion: {_err:?}");
                    Error::FunctionFailed
                })?;
        }

        debug!("Writing userid ");
        self.se
            .run_command(
                &WriteUserId::builder()
                    .object_id(se_id.key_id())
                    .data(&hex!("01020304"))
                    .build(),
                buf,
            )
            .map_err(|_err| {
                debug!("Failed WriteUserId: {_err:?}");
                Error::FunctionFailed
            })?;
        debug!("Creating session");
        let session_id = self
            .se
            .run_command(
                &CreateSession {
                    object_id: se_id.key_id(),
                },
                buf,
            )
            .map_err(|_err| {
                debug!("Failed to create session: {_err:?}");
                Error::FunctionFailed
            })?
            .session_id;
        debug!("Auth session");
        self.se
            .run_session_command(
                session_id,
                &VerifySessionUserId {
                    user_id: &hex!("01020304"),
                },
                buf,
            )
            .map_err(|_err| {
                debug!("Failed VerifySessionUserId: {_err:?}");
                Error::FunctionFailed
            })?;

        debug!("Deleting auth");
        self.se
            .run_session_command(
                session_id,
                &DeleteSecureObject {
                    object_id: se_id.intermediary_key_id(),
                },
                buf,
            )
            .map_err(|_err| {
                debug!("Failed to delete auth: {_err:?}");
                Error::FunctionFailed
            })?;
        debug!("Closing sess");
        self.se
            .run_session_command(session_id, &CloseSession {}, buf)
            .map_err(|_err| {
                debug!("Failed to close session: {_err:?}");
                Error::FunctionFailed
            })?;
        debug!("Deleting userid");
        self.se
            .run_command(
                &DeleteSecureObject {
                    object_id: se_id.key_id(),
                },
                buf,
            )
            .map_err(|_err| {
                debug!("Failed to delete user id: {_err:?}");
                Error::FunctionFailed
            })?;
        Ok(reply::Delete {
            success: keystore.delete_key(&key),
        })
    }

    fn derive_key<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::DeriveKey,
        core_keystore: &mut impl Keystore,
        se050_keystore: &mut impl Keystore,
        rng: &mut R,
        ns: NamespaceValue,
    ) -> Result<reply::DeriveKey, Error> {
        if req.additional_data.is_some() {
            return Err(Error::MechanismParamInvalid);
        }
        let (parsed_key, parsed_ty) =
            parse_key_id(req.base_key, ns).ok_or(Error::RequestNotAvailable)?;
        match parsed_key {
            ParsedObjectId::Pin(_)
            | ParsedObjectId::PinWithDerived(_)
            | ParsedObjectId::SaltValue(_) => return Err(Error::MechanismParamInvalid),
            ParsedObjectId::PersistentKey(k) => {
                self.derive_raw_key(req, k.0, core_keystore, parsed_ty, rng, ns)
            }
            ParsedObjectId::VolatileKey(k) => self.derive_volatile_key(
                req,
                k.0,
                parsed_ty,
                core_keystore,
                se050_keystore,
                rng,
                ns,
            ),
            ParsedObjectId::VolatileRsaKey(k) => {
                self.derive_volatile_rsa_key(req, k, parsed_ty, core_keystore, se050_keystore, ns)
            }
        }
    }

    fn reimport_volatile_key(
        &mut self,
        key: KeyId,
        kind: Kind,
        se050_keystore: &mut impl Keystore,
        obj: ObjectId,
    ) -> Result<(), Error> {
        let material = se050_keystore.load_key(Secrecy::Secret, Some(kind), &key)?;
        let parsed: VolatileKeyMaterialRef = trussed::cbor_deserialize(&material.material)
            .map_err(|_err| {
                error!("Failed to parsed volatile key data: {_err:?}");
                Error::CborError
            })?;

        assert_eq!(parsed.object_id.0, obj);
        self.se
            .run_command(
                &ImportObject::builder()
                    .object_id(obj)
                    .serialized_object(parsed.exported_material)
                    .build(),
                &mut [0; 128],
            )
            .map_err(|_err| {
                error!("Failed to re-import key for derive: {_err:?}");
                Error::FunctionFailed
            })?;
        Ok(())
    }

    fn derive_volatile_key<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::DeriveKey,
        key: ObjectId,
        ty: KeyType,
        core_keystore: &mut impl Keystore,
        se050_keystore: &mut impl Keystore,
        rng: &mut R,
        ns: NamespaceValue,
    ) -> Result<reply::DeriveKey, Error> {
        let kind = match ty {
            KeyType::Ed255 => Kind::Ed255,
            KeyType::X255 => Kind::X255,
            KeyType::P256 => Kind::P256,
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
                unreachable!("Volatile rsa keys are derived in a separate function")
            }
        };
        self.reimport_volatile_key(req.base_key, kind, se050_keystore, key)?;
        let res = self.derive_raw_key(req, key, core_keystore, ty, rng, ns)?;
        self.reselect()?;
        Ok(res)
    }

    fn derive_raw_key<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::DeriveKey,
        key: ObjectId,
        core_keystore: &mut impl Keystore,
        ty: KeyType,
        rng: &mut R,
        ns: NamespaceValue,
    ) -> Result<reply::DeriveKey, Error> {
        let buf = &mut [0; 1024];
        match ty {
            KeyType::Ed255 => {
                let material = self
                    .se
                    .run_command(&ReadObject::builder().object_id(key).build(), buf)
                    .map_err(|_err| {
                        error_now!("Failed to read key for derive: {_err:?}");
                        Error::FunctionFailed
                    })?;
                let result = core_keystore.store_key(
                    req.attributes.persistence,
                    Secrecy::Public,
                    Kind::Ed255,
                    material.data,
                )?;

                Ok(reply::DeriveKey { key: result })
            }
            KeyType::X255 => {
                let material = self
                    .se
                    .run_command(&ReadObject::builder().object_id(key).build(), buf)
                    .map_err(|_err| {
                        error_now!("Failed to read key for derive: {_err:?}");
                        Error::FunctionFailed
                    })?;
                debug_now!("Material: {material:02x?}");
                debug_now!("Len: {}", material.data.len());
                let result = core_keystore.store_key(
                    req.attributes.persistence,
                    Secrecy::Public,
                    Kind::X255,
                    material.data,
                )?;

                Ok(reply::DeriveKey { key: result })
            }
            KeyType::P256 => {
                let material = self
                    .se
                    .run_command(&ReadObject::builder().object_id(key).build(), buf)
                    .map_err(|_err| {
                        error_now!("Failed to read key for derive: {_err:?}");
                        Error::FunctionFailed
                    })?;
                debug_now!("Material: {material:02x?}");
                debug_now!("Len: {}", material.data.len());

                let result = core_keystore.store_key(
                    req.attributes.persistence,
                    Secrecy::Public,
                    Kind::P256,
                    material.data,
                )?;

                Ok(reply::DeriveKey { key: result })
            }
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
                todo!()
            }
        }
    }

    fn derive_volatile_rsa_key(
        &mut self,
        req: &request::DeriveKey,
        key: VolatileRsaObjectId,
        ty: KeyType,
        core_keystore: &mut impl Keystore,
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<reply::DeriveKey, Error> {
        todo!()
    }

    fn generate_key<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::GenerateKey,
        keystore: &mut impl Keystore,
        rng: &mut R,
        ns: NamespaceValue,
    ) -> Result<reply::GenerateKey, Error> {
        match req.attributes.persistence {
            Location::Volatile => self.generate_volatile_key(req, keystore, rng, ns),
            Location::Internal | Location::External => self.generate_persistent_key(req, rng, ns),
        }
    }

    fn generate_volatile_rsa_key<R: CryptoRng + RngCore>(
        &mut self,
        keystore: &mut impl Keystore,
        size: u16,
        kind: Kind,
        rng: &mut R,
        ns: NamespaceValue,
    ) -> Result<reply::GenerateKey, Error> {
        assert!(matches!(
            kind,
            Kind::Rsa2048 | Kind::Rsa3072 | Kind::Rsa4096
        ));
        let buf = &mut [0; 1024];
        let se_id = VolatileRsaObjectId::new(rng, ns);

        fn policy_for_intermediary(real_key: ObjectId) -> [Policy; 1] {
            [Policy {
                object_id: real_key,
                access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_DELETE),
            }]
        }
        fn policy_for_key(intermediary: ObjectId) -> [Policy; 2] {
            [
                Policy {
                    object_id: intermediary,
                    access_rule: ObjectAccessRule::from_flags(
                        ObjectPolicyFlags::ALLOW_SIGN
                            | ObjectPolicyFlags::ALLOW_VERIFY
                            | ObjectPolicyFlags::ALLOW_DEC
                            | ObjectPolicyFlags::ALLOW_ENC
                            | ObjectPolicyFlags::ALLOW_READ
                            | ObjectPolicyFlags::ALLOW_DELETE,
                    ),
                },
                Policy {
                    object_id: ObjectId::INVALID,
                    access_rule: ObjectAccessRule::from_flags(
                        ObjectPolicyFlags::ALLOW_DELETE | ObjectPolicyFlags::ALLOW_READ,
                    ),
                },
            ]
        }
        let key: [u8; 16] = self
            .se
            .run_command(&GetRandom { length: 16.into() }, buf)
            .or(Err(Error::FunctionFailed))?
            .data
            .try_into()
            .or(Err(Error::FunctionFailed))?;
        self.se
            .run_command(
                &WriteSymmKey::builder()
                    .is_auth(true)
                    .key_type(SymmKeyType::Aes)
                    .policy(PolicySet(&policy_for_intermediary(se_id.key_id())))
                    .object_id(se_id.intermediary_key_id())
                    .value(&key)
                    .build(),
                buf,
            )
            .or(Err(Error::FunctionFailed))?;
        self.se
            .run_command(
                &WriteRsaKey::builder()
                    .key_type(P1KeyType::KeyPair)
                    .policy(PolicySet(&policy_for_key(se_id.intermediary_key_id())))
                    .object_id(se_id.key_id())
                    .key_size(size.into())
                    .build(),
                buf,
            )
            .or(Err(Error::FunctionFailed))?;

        let key_material = cbor_serialize(
            &VolatileRsaKey {
                key_id: se_id,
                intermediary_key: key,
            },
            buf,
        )
        .or(Err(Error::CborError))?;
        let key = keystore.store_key(Location::Volatile, Secrecy::Secret, kind, key_material)?;
        Ok(reply::GenerateKey { key })
    }

    fn generate_volatile_key<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::GenerateKey,
        keystore: &mut impl Keystore,
        rng: &mut R,
        ns: NamespaceValue,
    ) -> Result<reply::GenerateKey, Error> {
        let (kind, ty) = match req.mechanism {
            Mechanism::Ed255 => (Kind::Ed255, KeyType::Ed255),
            Mechanism::X255 => (Kind::X255, KeyType::X255),
            Mechanism::P256 => (Kind::P256, KeyType::P256),
            Mechanism::Rsa2048Raw | Mechanism::Rsa2048Pkcs1v15 => {
                return self.generate_volatile_rsa_key(keystore, 2048, Kind::Rsa2048, rng, ns);
            }
            Mechanism::Rsa3072Raw | Mechanism::Rsa3072Pkcs1v15 => {
                return self.generate_volatile_rsa_key(keystore, 3072, Kind::Rsa3072, rng, ns);
            }
            Mechanism::Rsa4096Raw | Mechanism::Rsa4096Pkcs1v15 => {
                return self.generate_volatile_rsa_key(keystore, 4096, Kind::Rsa4096, rng, ns);
            }
            // Other mechanisms are filtered through the `supported` function
            _ => unreachable!(),
        };

        let buf = &mut [0; 1024];
        let object_id = VolatileObjectId::new(rng, ns);

        match req.mechanism {
            Mechanism::Ed255 => self
                .se
                .run_command(&generate_ed255(object_id.0, true), buf)
                .map_err(|_err| {
                    error_now!("Failed to generate volatile key: {_err:?}");
                    error_now!("Command: {:?}", generate_ed255(object_id.0, true));
                    Error::FunctionFailed
                })?,
            Mechanism::X255 => self
                .se
                .run_command(&generate_x255(object_id.0, true), buf)
                .map_err(|_err| {
                    // error_now!("Failed to generate volatile key: {_err:?}");
                    error_now!(
                        "Failed to generate volatile key: {_err:?}\nCommand: {:?}",
                        generate_x255(object_id.0, true)
                    );
                    Error::FunctionFailed
                })?,
            // TODO First write curve somehow
            Mechanism::P256 => self
                .se
                .run_command(&generate_p256(object_id.0, true), buf)
                .map_err(|_err| {
                    error_now!("Failed to generate volatile key: {_err:?}");
                    error_now!("Command: {:?}", generate_p256(object_id.0, true));
                    Error::FunctionFailed
                })?,
            _ => unreachable!(),
        }
        let exported = self
            .se
            .run_command(&ExportObject::builder().object_id(object_id.0).build(), buf)
            .or(Err(Error::FunctionFailed))?
            .data;
        let key = key_id_for_obj(object_id.0, ty);
        let material: Bytes<1024> = trussed::cbor_serialize_bytes(&VolatileKeyMaterialRef {
            object_id,
            exported_material: exported,
        })
        .or(Err(Error::FunctionFailed))?;
        keystore.overwrite_key(Location::Volatile, Secrecy::Secret, kind, &key, &material)?;

        // Remove any data from the transient storage
        self.reselect()?;
        Ok(reply::GenerateKey { key })
    }

    fn generate_persistent_key<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::GenerateKey,
        rng: &mut R,
        ns: NamespaceValue,
    ) -> Result<reply::GenerateKey, Error> {
        let buf = &mut [0; 1024];
        let object_id = PersistentObjectId::new(rng, ns);

        match req.mechanism {
            Mechanism::Ed255 => self
                .se
                .run_command(&generate_ed255(object_id.0, false), buf)
                .map_err(|_err| {
                    error_now!("Failed to generate key: {_err:?}");
                    Error::FunctionFailed
                })?,
            Mechanism::X255 => self
                .se
                .run_command(&generate_x255(object_id.0, false), buf)
                .map_err(|_err| {
                    error_now!("Failed to generate key: {_err:?}");
                    Error::FunctionFailed
                })?,

            // TODO First write curve somehow
            Mechanism::P256 => self
                .se
                .run_command(&generate_p256(object_id.0, false), buf)
                .map_err(|_err| {
                    error_now!("Failed to generate key: {_err:?}");
                    Error::FunctionFailed
                })?,
            Mechanism::P256Prehashed => return Err(Error::MechanismParamInvalid),
            Mechanism::Rsa2048Raw | Mechanism::Rsa2048Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id.0, 2048), buf)
                .map_err(|_err| {
                    error_now!("Failed to generate key: {_err:?}");
                    Error::FunctionFailed
                })?,
            Mechanism::Rsa3072Raw | Mechanism::Rsa3072Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id.0, 3072), buf)
                .map_err(|_err| {
                    error_now!("Failed to generate key: {_err:?}");
                    Error::FunctionFailed
                })?,
            Mechanism::Rsa4096Raw | Mechanism::Rsa4096Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id.0, 4096), buf)
                .map_err(|_err| {
                    error_now!("Failed to generate key: {_err:?}");
                    Error::FunctionFailed
                })?,
            // Other mechanisms are filtered through the `supported` function
            _ => unreachable!(),
        }

        let ty = match req.mechanism {
            Mechanism::Ed255 => KeyType::Ed255,

            Mechanism::X255 => KeyType::X255,

            // TODO First write curve somehow
            Mechanism::P256 => KeyType::P256,
            Mechanism::Rsa2048Raw | Mechanism::Rsa2048Pkcs1v15 => KeyType::Rsa2048,
            Mechanism::Rsa3072Raw | Mechanism::Rsa3072Pkcs1v15 => KeyType::Rsa3072,
            Mechanism::Rsa4096Raw | Mechanism::Rsa4096Pkcs1v15 => KeyType::Rsa4096,
            // Other mechanisms are filtered through the `supported` function
            _ => unreachable!(),
        };

        Ok(reply::GenerateKey {
            key: key_id_for_obj(object_id.0, ty),
        })
    }

    fn agree(
        &mut self,
        req: &request::Agree,
        core_keystore: &mut impl Keystore,
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<reply::Agree, Error> {
        let (priv_parsed_key, priv_parsed_ty) =
            parse_key_id(req.private_key, ns).ok_or(Error::RequestNotAvailable)?;

        let kind = match (req.mechanism, priv_parsed_ty) {
            (Mechanism::P256, KeyType::P256) => Kind::P256,
            (Mechanism::X255, KeyType::X255) => Kind::X255,
            _ => return Err(Error::WrongKeyKind),
        };

        if let ParsedObjectId::VolatileKey(priv_volatile) = priv_parsed_key {
            self.reimport_volatile_key(req.private_key, kind, se050_keystore, priv_volatile.0)?;
        }

        let (ParsedObjectId::VolatileKey(VolatileObjectId(priv_obj))
        | ParsedObjectId::PersistentKey(PersistentObjectId(priv_obj))) = priv_parsed_key
        else {
            return Err(Error::MechanismParamInvalid);
        };

        let pub_key = core_keystore.load_key(Secrecy::Public, Some(kind), &req.public_key)?;

        let buf = &mut [0; 256];
        let shared_secret = self
            .se
            .run_command(
                &EcdhGenerateSharedSecret {
                    key_id: priv_obj,
                    public_key: &pub_key.material,
                },
                buf,
            )
            .map_err(|_err| {
                debug_now!("Failed to perform agree: {_err:?}");
                Error::FunctionFailed
            })?
            .shared_secret;

        let flags = if req.attributes.serializable {
            key::Flags::SERIALIZABLE
        } else {
            key::Flags::empty()
        };
        let info = key::Info {
            kind: key::Kind::Shared(shared_secret.len()),
            flags,
        };

        let key_id = core_keystore.store_key(
            req.attributes.persistence,
            key::Secrecy::Secret,
            info,
            &shared_secret,
        )?;
        Ok(reply::Agree {
            shared_secret: key_id,
        })
    }

    fn rsa_decrypt_volatile<R: CryptoRng + RngCore>(
        &mut self,
        key_id: KeyId,
        object_id: VolatileRsaObjectId,
        ciphertext: &[u8],
        se050_keystore: &mut impl Keystore,
        algo: RsaEncryptionAlgo,
        kind: Kind,
        rng: &mut R,
    ) -> Result<reply::Decrypt, Error> {
        let buf = &mut [0; BUFFER_LEN];
        let data = se050_keystore.load_key(Secrecy::Secret, Some(kind), &key_id)?;
        let data: VolatileRsaKey = cbor_deserialize(&data.material).or(Err(Error::CborError))?;
        let session_id = self
            .se
            .run_command(
                &CreateSession {
                    object_id: object_id.intermediary_key_id(),
                },
                buf,
            )
            .map_err(|_err| {
                debug!("Failed to create session");
                Error::FunctionFailed
            })?
            .session_id;
        self.se
            .authenticate_aes128_session(session_id, &data.intermediary_key, rng)
            .map_err(|_err| {
                debug!("Failed to authenticate session");
                Error::FunctionFailed
            })?;
        let plaintext = self
            .se
            .run_session_command(
                session_id,
                &RsaDecrypt {
                    key_id: object_id.key_id(),
                    algo,
                    ciphertext,
                },
                buf,
            )
            .map_err(|_err| {
                error!("Failed to decrypt {_err:?}");
                Error::FunctionFailed
            })?
            .plaintext;
        self.se
            .run_session_command(session_id, &CloseSession {}, &mut [0; 128])
            .map_err(|_err| {
                error!("Failed to decrypt {_err:?}");
                Error::FunctionFailed
            })?;

        return Ok(reply::Decrypt {
            plaintext: Some(Bytes::from_slice(plaintext).map_err(|_err| Error::FunctionFailed)?),
        });
    }

    fn rsa_decrypt_persistent(
        &mut self,
        id: PersistentObjectId,
        ciphertext: &[u8],
        algo: RsaEncryptionAlgo,
    ) -> Result<reply::Decrypt, Error> {
        let buf = &mut [0; BUFFER_LEN];
        let res = self
            .se
            .run_command(
                &RsaDecrypt {
                    key_id: id.0,
                    algo,
                    ciphertext,
                },
                buf,
            )
            .map_err(|_err| {
                error!("Failed to decrypt {_err:?}");
                Error::FunctionFailed
            })?;
        return Ok(reply::Decrypt {
            plaintext: Some(
                Bytes::from_slice(res.plaintext).map_err(|_err| Error::FunctionFailed)?,
            ),
        });
    }

    fn decrypt<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::Decrypt,
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
        rng: &mut R,
    ) -> Result<reply::Decrypt, Error> {
        let (_bits, kind, raw) = bits_and_kind_from_mechanism(req.mechanism)?;
        let (key_id, key_type) = parse_key_id(req.key, ns).ok_or(Error::RequestNotAvailable)?;

        if !matches!(
            (key_type, kind),
            (KeyType::Rsa2048, Kind::Rsa2048)
                | (KeyType::Rsa3072, Kind::Rsa3072)
                | (KeyType::Rsa4096, Kind::Rsa4096)
        ) {
            return Err(Error::MechanismInvalid);
        }

        let algo = match raw {
            true => RsaEncryptionAlgo::NoPad,
            false => RsaEncryptionAlgo::Pkcs1,
        };

        match key_id {
            ParsedObjectId::VolatileRsaKey(key) => self.rsa_decrypt_volatile(
                req.key,
                key,
                &req.message,
                se050_keystore,
                algo,
                kind,
                rng,
            ),
            ParsedObjectId::PersistentKey(key) => {
                self.rsa_decrypt_persistent(key, &req.message, algo)
            }
            _ => return Err(Error::ObjectHandleInvalid),
        }
    }
}

const POLICY: PolicySet<'static> = PolicySet(&[Policy {
    object_id: ObjectId::INVALID,
    access_rule: ObjectAccessRule::from_flags(
        // We use `.union` rather than `|` for const
        ObjectPolicyFlags::ALLOW_READ
            .union(ObjectPolicyFlags::ALLOW_WRITE)
            .union(ObjectPolicyFlags::ALLOW_DELETE)
            .union(ObjectPolicyFlags::ALLOW_IMPORT_EXPORT)
            .union(ObjectPolicyFlags::ALLOW_VERIFY)
            .union(ObjectPolicyFlags::ALLOW_KA)
            .union(ObjectPolicyFlags::ALLOW_ENC)
            .union(ObjectPolicyFlags::ALLOW_DEC)
            .union(ObjectPolicyFlags::ALLOW_SIGN),
    ),
}]);

fn generate_ed255(object_id: ObjectId, transient: bool) -> WriteEcKey<'static> {
    WriteEcKey::builder()
        .transient(transient)
        .key_type(P1KeyType::KeyPair)
        .policy(POLICY)
        .object_id(object_id)
        .curve(EcCurve::IdEccEd25519)
        .build()
}

fn generate_x255(object_id: ObjectId, transient: bool) -> WriteEcKey<'static> {
    WriteEcKey::builder()
        .transient(transient)
        .key_type(P1KeyType::KeyPair)
        .policy(POLICY)
        .object_id(object_id)
        .curve(EcCurve::IdEccMontDh25519)
        .build()
}

fn generate_p256(object_id: ObjectId, transient: bool) -> WriteEcKey<'static> {
    WriteEcKey::builder()
        .transient(transient)
        .key_type(P1KeyType::KeyPair)
        .policy(POLICY)
        .object_id(object_id)
        .curve(EcCurve::NistP256)
        .build()
}

fn generate_rsa(object_id: ObjectId, size: u16) -> WriteRsaKey<'static> {
    WriteRsaKey::builder()
        .key_type(P1KeyType::KeyPair)
        .policy(POLICY)
        .object_id(object_id)
        .key_size(size.into())
        .build()
}

fn supported(mechanism: Mechanism) -> bool {
    matches!(
        mechanism,
        Mechanism::Ed255
            | Mechanism::X255
            | Mechanism::P256
            | Mechanism::P256Prehashed
            | Mechanism::Rsa2048Raw
            | Mechanism::Rsa3072Raw
            | Mechanism::Rsa4096Raw
            | Mechanism::Rsa2048Pkcs1v15
            | Mechanism::Rsa3072Pkcs1v15
            | Mechanism::Rsa4096Pkcs1v15
    )
}

impl<Twi: I2CForT1, D: DelayUs<u32>> Se050Backend<Twi, D> {
    fn core_request_internal<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut trussed::types::CoreContext,
        backend_ctx: &mut Context,
        request: &Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, Error> {
        self.configure()?;
        debug_now!("Trussed core SE050 request: {request:?}");

        // FIXME: Have a real implementation from trussed
        let mut backend_path = core_ctx.path.clone();
        backend_path.push(&PathBuf::from(BACKEND_DIR));
        backend_path.push(&PathBuf::from(CORE_DIR));
        let _fs = &mut resources.filestore(backend_path.clone());
        let _global_fs = &mut resources.filestore(PathBuf::from(BACKEND_DIR));
        let rng = &mut resources.rng()?;
        let _client_id = core_ctx.path.clone();

        let se050_keystore = &mut resources.keystore(backend_path)?;
        let core_keystore = &mut resources.keystore(core_ctx.path.clone())?;

        let backend_ctx = backend_ctx.with_namespace(&self.ns, &core_ctx.path);
        let ns = backend_ctx.ns;

        Ok(match request {
            Request::RandomBytes(request::RandomBytes { count }) => self.random_bytes(*count)?,
            Request::Agree(req) if supported(req.mechanism) => {
                self.agree(req, core_keystore, se050_keystore, ns)?.into()
            }
            Request::Decrypt(req) if supported(req.mechanism) => {
                self.decrypt(req, se050_keystore, ns, rng)?.into()
            }
            Request::DeriveKey(req) if supported(req.mechanism) => self
                .derive_key(req, core_keystore, se050_keystore, rng, ns)?
                .into(),
            Request::DeserializeKey(req) if supported(req.mechanism) => todo!(),
            Request::Encrypt(req) if supported(req.mechanism) => todo!(),
            Request::Delete(request::Delete { key }) => {
                self.delete(key, ns, se050_keystore)?.into()
            }
            Request::Clear(_req) => todo!(),
            Request::DeleteAllKeys(_req) => todo!(),
            Request::Exists(req) if supported(req.mechanism) => todo!(),
            Request::GenerateKey(req) if supported(req.mechanism) => {
                self.generate_key(req, se050_keystore, rng, ns)?.into()
            }
            Request::GenerateSecretKey(_req) => todo!(),
            Request::SerializeKey(req) if supported(req.mechanism) => todo!(),
            Request::Sign(req) if supported(req.mechanism) => todo!(),
            Request::UnsafeInjectKey(req) if supported(req.mechanism) => todo!(),
            Request::UnwrapKey(req) if supported(req.mechanism) => todo!(),
            Request::Verify(req) if supported(req.mechanism) => todo!(),
            Request::WrapKey(req) if supported(req.mechanism) => todo!(),
            _ => return Err(Error::RequestNotAvailable),
        })
    }
}

impl<Twi: I2CForT1, D: DelayUs<u32>> Backend for Se050Backend<Twi, D> {
    type Context = Context;

    fn request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut trussed::types::CoreContext,
        backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, Error> {
        debug_now!("Got request: {request:?}");
        let res = self.core_request_internal(core_ctx, backend_ctx, request, resources);
        debug_now!("Got res: {res:?}");
        res
    }
}
