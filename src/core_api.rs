//! Implementations of the core APIs for the SE050 backend

use cbor_smol::cbor_serialize;
use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use littlefs2::path::PathBuf;
use rand::{CryptoRng, RngCore};
use se05x::{
    se05x::{
        commands::{
            CheckObjectExists, CloseSession, CreateSession, DeleteSecureObject,
            EcdhGenerateSharedSecret, ExportObject, GetRandom, ImportObject, VerifySessionUserId,
            WriteEcKey, WriteRsaKey, WriteSymmKey, WriteUserId,
        },
        policies::{ObjectAccessRule, ObjectPolicyFlags, Policy, PolicySet},
        EcCurve, ObjectId, P1KeyType, ProcessSessionCmd, Se05XResult, SymmKeyType,
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
    types::{KeyId, Location, Mechanism, Message},
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
        let (parsed_key, _parsed_ty, parsed_priv) = parse_key_id(*key, ns).unwrap();
        match (parsed_key, parsed_priv) {
            (
                ParsedObjectId::Pin(_)
                | ParsedObjectId::PinWithDerived(_)
                | ParsedObjectId::SaltValue(_),
                _,
            ) => return Err(Error::ObjectHandleInvalid),
            (ParsedObjectId::PersistentKey(PersistentObjectId(obj)), _) => {
                self.delete_persistent_key(obj)
            }
            (ParsedObjectId::VolatileKey(VolatileObjectId(obj)), Privacy::Secret) => {
                self.delete_volatile_key(&key, obj, keystore)
            }
            (ParsedObjectId::VolatileKey(VolatileObjectId(_obj)), Privacy::Public) => {
                // TODO Check that public key material stays for transient keys
                // If not, we will need to read the public keys and store them when deriving
                Ok(reply::Delete { success: true })
            }
            (ParsedObjectId::VolatileRsaKey(obj), Privacy::Secret) => {
                self.delete_volatile_rsa_key(*key, obj, keystore)
            }
            (ParsedObjectId::VolatileRsaKey(_obj), Privacy::Public) => {
                // Nothing to do since the public RSA key is actually the same object ID as the private key
                Ok(reply::Delete { success: true })
            }
        }
    }

    fn delete_persistent_key(&mut self, object_id: ObjectId) -> Result<reply::Delete, Error> {
        let buf = &mut [0; 1024];
        self.se
            .run_command(&DeleteSecureObject { object_id }, buf)
            .or(Err(Error::FunctionFailed))?;
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
            .run_command(
                &ProcessSessionCmd {
                    session_id,
                    apdu: VerifySessionUserId {
                        user_id: &hex!("01020304"),
                    },
                },
                buf,
            )
            .map_err(|_err| {
                debug!("Failed VerifySessionUserId: {_err:?}");
                Error::FunctionFailed
            })?;

        debug!("Deleting auth");
        self.se
            .run_command(
                &ProcessSessionCmd {
                    session_id,
                    apdu: DeleteSecureObject {
                        object_id: se_id.intermediary_key_id(),
                    },
                },
                buf,
            )
            .map_err(|_err| {
                debug!("Failed to delete auth: {_err:?}");
                Error::FunctionFailed
            })?;
        debug!("Closing sess");
        self.se
            .run_command(
                &ProcessSessionCmd {
                    session_id,
                    apdu: CloseSession {},
                },
                buf,
            )
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
                .or(Err(Error::FunctionFailed))?,
            Mechanism::X255 => self
                .se
                .run_command(&generate_ed255(object_id.0, true), buf)
                .or(Err(Error::FunctionFailed))?,
            // TODO First write curve somehow
            Mechanism::P256 => self
                .se
                .run_command(&generate_ed255(object_id.0, true), buf)
                .or(Err(Error::FunctionFailed))?,
            _ => unreachable!(),
        }
        let exported = self
            .se
            .run_command(&ExportObject::builder().object_id(object_id.0).build(), buf)
            .or(Err(Error::FunctionFailed))?
            .data;
        let key = key_id_for_obj(object_id.0, Privacy::Secret, ty);
        let material: Bytes<1024> = trussed::cbor_serialize_bytes(&VolatileKeyMaterialRef {
            object_id,
            exported_material: exported,
        })
        .or(Err(Error::FunctionFailed))?;
        keystore.overwrite_key(Location::Volatile, Secrecy::Secret, kind, &key, &material)?;

        // Remove any data from the transient storage
        self.se.enable().or(Err(Error::FunctionFailed))?;
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
                .or(Err(Error::FunctionFailed))?,

            Mechanism::X255 => self
                .se
                .run_command(&generate_x255(object_id.0, false), buf)
                .or(Err(Error::FunctionFailed))?,

            // TODO First write curve somehow
            Mechanism::P256 => self
                .se
                .run_command(&generate_p256(object_id.0, false), buf)
                .or(Err(Error::FunctionFailed))?,
            Mechanism::P256Prehashed => return Err(Error::MechanismParamInvalid),
            Mechanism::Rsa2048Raw | Mechanism::Rsa2048Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id.0, 2048), buf)
                .or(Err(Error::FunctionFailed))?,
            Mechanism::Rsa3072Raw | Mechanism::Rsa3072Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id.0, 3072), buf)
                .or(Err(Error::FunctionFailed))?,
            Mechanism::Rsa4096Raw | Mechanism::Rsa4096Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id.0, 4096), buf)
                .or(Err(Error::FunctionFailed))?,
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
            key: key_id_for_obj(object_id.0, Privacy::Secret, ty),
        })
    }

    fn agree(
        &mut self,
        req: &request::Agree,
        se050_keystore: &mut impl Keystore,
        core_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<reply::Agree, Error> {
        let (parsed_key, parsed_ty, parsed_priv) = parse_key_id(req.private_key, ns).unwrap();
        if parsed_priv != Privacy::Secret {
            return Err(Error::ObjectHandleInvalid);
        }

        match parsed_key {
            ParsedObjectId::VolatileKey(obj) => {
                self.agree_volatile(req, obj, parsed_ty, se050_keystore, core_keystore)
            }
            ParsedObjectId::PersistentKey(obj) => {
                self.agree_persistent(req, obj, parsed_ty, core_keystore)
            }
            _ => Err(Error::ObjectHandleInvalid),
        }
    }

    fn agree_persistent(
        &mut self,
        req: &request::Agree,
        key: PersistentObjectId,
        ty: KeyType,
        core_keystore: &mut impl Keystore,
    ) -> Result<reply::Agree, Error> {
        let kind = match (req.mechanism, ty) {
            (Mechanism::P256, KeyType::P256) => Kind::P256,
            (Mechanism::X255, KeyType::X255) => Kind::X255,
            _ => return Err(Error::MechanismParamInvalid),
        };

        let pub_key = core_keystore.load_key(Secrecy::Public, Some(kind), &req.public_key)?;

        let buf = &mut [0; 1024];

        let shared_secret = self
            .se
            .run_command(
                &EcdhGenerateSharedSecret {
                    key_id: key.0,
                    public_key: &pub_key.material,
                },
                buf,
            )
            .or(Err(Error::FunctionFailed))?
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

    fn agree_volatile(
        &mut self,
        req: &request::Agree,
        obj_id: VolatileObjectId,
        ty: KeyType,
        se050_keystore: &mut impl Keystore,
        core_keystore: &mut impl Keystore,
    ) -> Result<reply::Agree, Error> {
        let kind = match (req.mechanism, ty) {
            (Mechanism::P256, KeyType::P256) => Kind::P256,
            (Mechanism::X255, KeyType::X255) => Kind::X255,
            _ => return Err(Error::MechanismParamInvalid),
        };

        let priv_key = se050_keystore.load_key(Secrecy::Secret, Some(kind), &req.private_key)?;
        let priv_key: VolatileKeyMaterialRef =
            cbor_smol::cbor_deserialize(&priv_key.material).or(Err(Error::CborError))?;
        if priv_key.object_id != obj_id {
            error!(
                "Incorrect object id: {:02x?} {:02x?}",
                priv_key.object_id, obj_id
            );
            return Err(Error::FunctionFailed);
        }

        let pub_key = core_keystore.load_key(Secrecy::Public, Some(kind), &req.public_key)?;

        let buf = &mut [0; 1024];

        self.se
            .run_command(
                &ImportObject::builder()
                    .object_id(priv_key.object_id.0)
                    .serialized_object(priv_key.exported_material)
                    .build(),
                buf,
            )
            .or(Err(Error::FunctionFailed))?;

        let shared_secret = self
            .se
            .run_command(
                &EcdhGenerateSharedSecret {
                    key_id: *priv_key.object_id,
                    public_key: &pub_key.material,
                },
                buf,
            )
            .or(Err(Error::FunctionFailed))?
            .shared_secret;

        // Clear volatile data
        self.se.enable().or(Err(Error::FunctionFailed))?;

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
}

fn generate_ed255(object_id: ObjectId, transient: bool) -> WriteEcKey<'static> {
    WriteEcKey::builder()
        .transient(transient)
        .key_type(P1KeyType::KeyPair)
        .object_id(object_id)
        .curve(EcCurve::IdEccEd25519)
        .build()
}

fn generate_x255(object_id: ObjectId, transient: bool) -> WriteEcKey<'static> {
    WriteEcKey::builder()
        .transient(transient)
        .key_type(P1KeyType::KeyPair)
        .object_id(object_id)
        .curve(EcCurve::IdEccMontDh25519)
        .build()
}

fn generate_p256(object_id: ObjectId, transient: bool) -> WriteEcKey<'static> {
    WriteEcKey::builder()
        .transient(transient)
        .key_type(P1KeyType::KeyPair)
        .object_id(object_id)
        .curve(EcCurve::NistP256)
        .build()
}

fn generate_rsa(object_id: ObjectId, size: u16) -> WriteRsaKey<'static> {
    WriteRsaKey::builder()
        .key_type(P1KeyType::KeyPair)
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

impl<Twi: I2CForT1, D: DelayUs<u32>> Backend for Se050Backend<Twi, D> {
    type Context = Context;

    fn request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut trussed::types::CoreContext,
        backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, Error> {
        self.enable()?;
        debug_now!("Trussed Auth request: {request:?}");

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
                self.agree(req, se050_keystore, core_keystore, ns)?.into()
            }
            Request::Decrypt(req) if supported(req.mechanism) => todo!(),
            Request::DeriveKey(req) if supported(req.mechanism) => todo!(),
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
