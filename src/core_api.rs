//! Implementations of the core APIs for the SE050 backend

use cbor_smol::cbor_serialize;
use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use littlefs2::path::PathBuf;
use rand::{CryptoRng, RngCore};
use se05x::{
    se05x::{
        commands::{
            CheckObjectExists, CloseSession, CreateSession, DeleteSecureObject, ExportObject,
            GetRandom, VerifySessionUserId, WriteEcKey, WriteRsaKey, WriteSymmKey, WriteUserId,
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
    key::{Kind, Secrecy},
    service::Keystore,
    types::{KeyId, Location, Mechanism, Message},
    Bytes, Error,
};

use crate::{generate_object_id, Context, Se050Backend, BACKEND_DIR};

const BUFFER_LEN: usize = 2048;
const CORE_DIR: &str = "se050-core";

/// Persistent metadata for
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PersistentMetadata {
    /// The key is a standard non-transient key
    None,
    /// The key is a volatile (transient) ECC key
    StandardVolatile,
    /// The key is a volatile RSA key thas therefore is actually not transient and is protected by an intemediary AES key.
    RsaVolatile { intermediary: ObjectId },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PersistentKeyMaterial {
    object_id: ObjectId,
    metatada: PersistentMetadata,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VolatileKeyMaterial {
    object_id: ObjectId,
    persistent_metadata: KeyId,
    exported_material: Bytes<1024>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VolatileKeyMaterialRef<'a> {
    object_id: ObjectId,
    persistent_metadata: KeyId,
    #[serde(serialize_with = "serde_bytes::serialize")]
    exported_material: &'a [u8],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VolatileRsaKey {
    object_id: ObjectId,
    intermediary_object_id: ObjectId,
    metadata_id: KeyId,
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
        keystore: &mut impl Keystore,
    ) -> Result<reply::Delete, Error> {
        // If the key is not found in the se050 keystore, pass the call to the core API
        // The backend only stores secret keys (even public keys are actually the secret part)
        let loaded_key = keystore
            .load_key(Secrecy::Secret, None, key)
            .or(Err(Error::MechanismNotAvailable))?;
        let material: PersistentKeyMaterial =
            cbor_smol::cbor_deserialize(&loaded_key.material).or(Err(Error::FunctionFailed))?;
        match material.metatada {
            PersistentMetadata::None | PersistentMetadata::StandardVolatile => {
                self.delete_standard_key(material.object_id, key, keystore)
            }
            PersistentMetadata::RsaVolatile { intermediary } => {
                self.delete_volatile_rsa_key(material.object_id, intermediary, key, keystore)
            }
        }
    }

    fn delete_standard_key(
        &mut self,
        object_id: ObjectId,
        key: &KeyId,
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
        key: ObjectId,
        intermediary: ObjectId,
        metadata: &KeyId,
        keystore: &mut impl Keystore,
    ) -> Result<reply::Delete, Error> {
        let buf = &mut [0; 1024];

        let exists = self
            .se
            .run_command(&CheckObjectExists { object_id: key }, buf)
            .map_err(|_err| {
                debug!("Failed existence check: {_err:?}");
                Error::FunctionFailed
            })?
            .result;
        if exists == Se05XResult::Success {
            debug!("Deleting key");
            self.se
                .run_command(&DeleteSecureObject { object_id: key }, buf)
                .map_err(|_err| {
                    debug!("Failed deletion: {_err:?}");
                    Error::FunctionFailed
                })?;
        }

        debug!("Writing userid ");
        self.se
            .run_command(
                &WriteUserId::builder()
                    .object_id(key)
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
            .run_command(&CreateSession { object_id: key }, buf)
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
                        object_id: intermediary,
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
            .run_command(&DeleteSecureObject { object_id: key }, buf)
            .map_err(|_err| {
                debug!("Failed to delete user id: {_err:?}");
                Error::FunctionFailed
            })?;
        Ok(reply::Delete {
            success: keystore.delete_key(metadata),
        })
    }

    fn generate_key<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::GenerateKey,
        keystore: &mut impl Keystore,
        rng: &mut R,
    ) -> Result<reply::GenerateKey, Error> {
        match req.attributes.persistence {
            Location::Volatile => self.generate_volatile_key(req, keystore, rng),
            Location::Internal | Location::External => {
                self.generate_persistent_key(req, keystore, rng)
            }
        }
    }

    fn generate_volatile_rsa_key<R: CryptoRng + RngCore>(
        &mut self,
        keystore: &mut impl Keystore,
        size: u16,
        kind: Kind,
        rng: &mut R,
    ) -> Result<reply::GenerateKey, Error> {
        let buf = &mut [0; 1024];
        let real_key_id = generate_object_id(rng);
        let intermediary_id = generate_object_id(rng);

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
                    .policy(PolicySet(&policy_for_intermediary(real_key_id)))
                    .object_id(intermediary_id)
                    .value(&key)
                    .build(),
                buf,
            )
            .or(Err(Error::FunctionFailed))?;
        self.se
            .run_command(
                &WriteRsaKey::builder()
                    .key_type(P1KeyType::KeyPair)
                    .policy(PolicySet(&policy_for_key(intermediary_id)))
                    .object_id(real_key_id)
                    .key_size(size.into())
                    .build(),
                buf,
            )
            .or(Err(Error::FunctionFailed))?;

        let metadata_material = cbor_serialize(
            &PersistentKeyMaterial {
                object_id: real_key_id,
                metatada: PersistentMetadata::RsaVolatile {
                    intermediary: intermediary_id,
                },
            },
            buf,
        )
        .or(Err(Error::CborError))?;
        let metadata_id = keystore.store_key(
            self.key_metadata_location,
            Secrecy::Secret,
            kind,
            metadata_material,
        )?;

        let key_material = cbor_serialize(
            &VolatileRsaKey {
                object_id: real_key_id,
                intermediary_object_id: intermediary_id,
                metadata_id,
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
    ) -> Result<reply::GenerateKey, Error> {
        let kind = match req.mechanism {
            Mechanism::Ed255 => Kind::Ed255,
            Mechanism::X255 => Kind::X255,
            Mechanism::P256 => Kind::P256,
            Mechanism::Rsa2048Raw | Mechanism::Rsa2048Pkcs1v15 => {
                return self.generate_volatile_rsa_key(keystore, 2048, Kind::Rsa2048, rng);
            }
            Mechanism::Rsa3072Raw | Mechanism::Rsa3072Pkcs1v15 => {
                return self.generate_volatile_rsa_key(keystore, 3072, Kind::Rsa3072, rng);
            }
            Mechanism::Rsa4096Raw | Mechanism::Rsa4096Pkcs1v15 => {
                return self.generate_volatile_rsa_key(keystore, 4096, Kind::Rsa4096, rng);
            }
            // Other mechanisms are filtered through the `supported` function
            _ => unreachable!(),
        };

        let buf = &mut [0; 1024];
        let object_id = generate_object_id(rng);

        match req.mechanism {
            Mechanism::Ed255 => self
                .se
                .run_command(&generate_ed255(object_id, true), buf)
                .or(Err(Error::FunctionFailed))?,
            Mechanism::X255 => self
                .se
                .run_command(&generate_ed255(object_id, true), buf)
                .or(Err(Error::FunctionFailed))?,
            // TODO First write curve somehow
            Mechanism::P256 => self
                .se
                .run_command(&generate_ed255(object_id, true), buf)
                .or(Err(Error::FunctionFailed))?,
            _ => unreachable!(),
        }
        let metadata_material = cbor_serialize(
            &PersistentKeyMaterial {
                object_id,
                metatada: PersistentMetadata::StandardVolatile,
            },
            buf,
        )
        .or(Err(Error::CborError))?;
        let metadata_id = keystore.store_key(
            req.attributes.persistence,
            Secrecy::Secret,
            kind,
            metadata_material,
        )?;
        let exported = self
            .se
            .run_command(&ExportObject::builder().object_id(object_id).build(), buf)
            .or(Err(Error::FunctionFailed))?
            .data;
        let material: Bytes<1024> = trussed::cbor_serialize_bytes(&VolatileKeyMaterialRef {
            object_id,
            persistent_metadata: metadata_id,
            exported_material: exported,
        })
        .or(Err(Error::FunctionFailed))?;
        let key = keystore
            .store_key(Location::Volatile, Secrecy::Secret, kind, &material)
            .or(Err(Error::FunctionFailed))?;

        // Remove any data from the transient storage
        self.se.enable().or(Err(Error::FunctionFailed))?;
        Ok(reply::GenerateKey { key })
    }

    fn generate_persistent_key<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::GenerateKey,
        keystore: &mut impl Keystore,
        rng: &mut R,
    ) -> Result<reply::GenerateKey, Error> {
        let buf = &mut [0; 1024];
        let object_id = generate_object_id(rng);

        match req.mechanism {
            Mechanism::Ed255 => self
                .se
                .run_command(&generate_ed255(object_id, false), buf)
                .or(Err(Error::FunctionFailed))?,

            Mechanism::X255 => self
                .se
                .run_command(&generate_x255(object_id, false), buf)
                .or(Err(Error::FunctionFailed))?,

            // TODO First write curve somehow
            Mechanism::P256 => self
                .se
                .run_command(&generate_p256(object_id, false), buf)
                .or(Err(Error::FunctionFailed))?,
            Mechanism::P256Prehashed => return Err(Error::MechanismParamInvalid),
            Mechanism::Rsa2048Raw | Mechanism::Rsa2048Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id, 2048), buf)
                .or(Err(Error::FunctionFailed))?,
            Mechanism::Rsa3072Raw | Mechanism::Rsa3072Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id, 3072), buf)
                .or(Err(Error::FunctionFailed))?,
            Mechanism::Rsa4096Raw | Mechanism::Rsa4096Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id, 4096), buf)
                .or(Err(Error::FunctionFailed))?,
            // Other mechanisms are filtered through the `supported` function
            _ => unreachable!(),
        }

        let kind = match req.mechanism {
            Mechanism::Ed255 => Kind::Ed255,

            Mechanism::X255 => Kind::X255,

            // TODO First write curve somehow
            Mechanism::P256 => Kind::P256,
            Mechanism::Rsa2048Raw | Mechanism::Rsa2048Pkcs1v15 => Kind::Rsa2048,
            Mechanism::Rsa3072Raw | Mechanism::Rsa3072Pkcs1v15 => Kind::Rsa3072,
            Mechanism::Rsa4096Raw | Mechanism::Rsa4096Pkcs1v15 => Kind::Rsa4096,
            // Other mechanisms are filtered through the `supported` function
            _ => unreachable!(),
        };

        let material = cbor_serialize(
            &PersistentKeyMaterial {
                object_id,
                metatada: PersistentMetadata::None,
            },
            buf,
        )
        .or(Err(Error::CborError))?;
        let key =
            keystore.store_key(req.attributes.persistence, Secrecy::Secret, kind, material)?;
        Ok(reply::GenerateKey { key })
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
        _backend_ctx: &mut Self::Context,
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
        let _core_keystore = &mut resources.keystore(core_ctx.path.clone())?;

        Ok(match request {
            Request::RandomBytes(request::RandomBytes { count }) => self.random_bytes(*count)?,
            Request::Agree(req) if supported(req.mechanism) => todo!(),
            Request::Decrypt(req) if supported(req.mechanism) => todo!(),
            Request::DeriveKey(req) if supported(req.mechanism) => todo!(),
            Request::DeserializeKey(req) if supported(req.mechanism) => todo!(),
            Request::Encrypt(req) if supported(req.mechanism) => todo!(),
            Request::Delete(request::Delete { key }) => self.delete(key, se050_keystore)?.into(),
            Request::DeleteAllKeys(_req) => todo!(),
            Request::Exists(req) if supported(req.mechanism) => todo!(),
            Request::GenerateKey(req) if supported(req.mechanism) => {
                self.generate_key(req, se050_keystore, rng)?.into()
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
