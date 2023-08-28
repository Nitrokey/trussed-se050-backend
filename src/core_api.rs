//! Implementations of the core APIs for the SE050 backend

use cbor_smol::cbor_serialize;
use embedded_hal::blocking::delay::DelayUs;
use littlefs2::path::PathBuf;
use rand::{CryptoRng, RngCore};
use se05x::{
    se05x::{
        commands::{GetRandom, WriteEcKey, WriteRsaKey},
        EcCurve, ObjectId, P1KeyType,
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
    types::{Location, Mechanism, Message},
    Bytes,
};

use crate::{generate_object_id, Context, Se050Backend, BACKEND_DIR};

const BUFFER_LEN: usize = 2048;
const CORE_DIR: &str = "se050-core";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PersistentKeyMaterial {
    object_id: ObjectId,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VolatileKeyMaterial {
    object_id: ObjectId,
    exported_material: Bytes<1024>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VolatileRsaKeyMaterial {
    object_id: ObjectId,
    exported_rsa_mod: Bytes<512>,
    exported_e: Bytes<512>,
    exported_d: Bytes<512>,
}

impl<Twi: I2CForT1, D: DelayUs<u32>> Se050Backend<Twi, D> {
    fn random_bytes(&mut self, count: usize) -> Result<trussed::Reply, trussed::Error> {
        if count >= MAX_MESSAGE_LENGTH {
            return Err(trussed::Error::MechanismParamInvalid);
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
                trussed::Error::FunctionFailed
            })?;
        if res.data.len() != count {
            error!("Bad random length");
            return Err(trussed::Error::FunctionFailed);
        }
        Ok(reply::RandomBytes {
            bytes: Message::from_slice(res.data).unwrap(),
        }
        .into())
    }

    fn generate_key<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::GenerateKey,
        keystore: &mut impl Keystore,
        rng: &mut R,
    ) -> Result<reply::GenerateKey, trussed::Error> {
        match req.attributes.persistence {
            Location::Volatile => todo!(),
            Location::Internal | Location::External => {
                self.generate_persistent_key(req, keystore, rng)
            }
        }
    }

    fn generate_persistent_key<R: CryptoRng + RngCore>(
        &mut self,
        req: &request::GenerateKey,
        keystore: &mut impl Keystore,
        rng: &mut R,
    ) -> Result<reply::GenerateKey, trussed::Error> {
        let buf = &mut [0; 1024];
        let object_id = generate_object_id(rng);

        match req.mechanism {
            Mechanism::Ed255 => self
                .se
                .run_command(&generate_ed255(object_id), buf)
                .or(Err(trussed::Error::FunctionFailed))?,

            Mechanism::X255 => self
                .se
                .run_command(&generate_x255(object_id), buf)
                .or(Err(trussed::Error::FunctionFailed))?,

            // TODO First write curve somehow
            Mechanism::P256 => self
                .se
                .run_command(&generate_p256(object_id), buf)
                .or(Err(trussed::Error::FunctionFailed))?,
            Mechanism::P256Prehashed => return Err(trussed::Error::MechanismParamInvalid),
            Mechanism::Rsa2048Raw | Mechanism::Rsa2048Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id, 2048), buf)
                .or(Err(trussed::Error::FunctionFailed))?,
            Mechanism::Rsa3072Raw | Mechanism::Rsa3072Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id, 3072), buf)
                .or(Err(trussed::Error::FunctionFailed))?,
            Mechanism::Rsa4096Raw | Mechanism::Rsa4096Pkcs1v15 => self
                .se
                .run_command(&generate_rsa(object_id, 4096), buf)
                .or(Err(trussed::Error::FunctionFailed))?,
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

        let material = cbor_serialize(&PersistentKeyMaterial { object_id }, buf)
            .or(Err(trussed::Error::CborError))?;
        let key =
            keystore.store_key(req.attributes.persistence, Secrecy::Secret, kind, material)?;
        Ok(reply::GenerateKey { key })
    }
}

fn generate_ed255(object_id: ObjectId) -> WriteEcKey<'static> {
    WriteEcKey {
        transient: false,
        is_auth: false,
        key_type: Some(P1KeyType::KeyPair),
        policy: None,
        max_attempts: None,
        object_id,
        curve: Some(EcCurve::IdEccEd25519),
        private_key: None,
        public_key: None,
    }
}

fn generate_x255(object_id: ObjectId) -> WriteEcKey<'static> {
    WriteEcKey {
        transient: false,
        is_auth: false,
        key_type: Some(P1KeyType::KeyPair),
        policy: None,
        max_attempts: None,
        object_id,
        curve: Some(EcCurve::IdEccMontDh25519),
        private_key: None,
        public_key: None,
    }
}

fn generate_p256(object_id: ObjectId) -> WriteEcKey<'static> {
    WriteEcKey {
        transient: false,
        is_auth: false,
        key_type: Some(P1KeyType::KeyPair),
        policy: None,
        max_attempts: None,
        object_id,
        curve: Some(EcCurve::IdEccMontDh25519),
        private_key: None,
        public_key: None,
    }
}

fn generate_rsa(object_id: ObjectId, size: u16) -> WriteRsaKey<'static> {
    WriteRsaKey {
        transient: false,
        is_auth: false,
        key_type: Some(P1KeyType::KeyPair),
        policy: None,
        max_attempts: None,
        object_id,
        key_size: Some(size.into()),
        p: None,
        q: None,
        dp: None,
        dq: None,
        inv_q: None,
        e: None,
        d: None,
        n: None,
    }
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
    ) -> Result<trussed::Reply, trussed::Error> {
        self.enable()?;
        debug_now!("Trussed Auth request: {request:?}");

        // FIXME: Have a real implementation from trussed
        let mut backend_path = core_ctx.path.clone();
        backend_path.push(&PathBuf::from(BACKEND_DIR));
        backend_path.push(&PathBuf::from(CORE_DIR));
        let _fs = &mut resources.filestore(backend_path);
        let _global_fs = &mut resources.filestore(PathBuf::from(BACKEND_DIR));
        let rng = &mut resources.rng()?;
        let _client_id = core_ctx.path.clone();
        let keystore = &mut resources.keystore(core_ctx)?;

        Ok(match request {
            Request::RandomBytes(request::RandomBytes { count }) => self.random_bytes(*count)?,
            Request::Agree(req) if supported(req.mechanism) => todo!(),
            Request::Decrypt(req) if supported(req.mechanism) => todo!(),
            Request::DeriveKey(req) if supported(req.mechanism) => todo!(),
            Request::DeserializeKey(req) if supported(req.mechanism) => todo!(),
            Request::Encrypt(req) if supported(req.mechanism) => todo!(),
            Request::Delete(_req) => todo!(),
            Request::DeleteAllKeys(_req) => todo!(),
            Request::Exists(req) if supported(req.mechanism) => todo!(),
            Request::GenerateKey(req) if supported(req.mechanism) => {
                self.generate_key(req, keystore, rng)?.into()
            }
            Request::GenerateSecretKey(_req) => todo!(),
            Request::SerializeKey(req) if supported(req.mechanism) => todo!(),
            Request::Sign(req) if supported(req.mechanism) => todo!(),
            Request::UnsafeInjectKey(req) if supported(req.mechanism) => todo!(),
            Request::UnsafeInjectSharedKey(_req) => todo!(),
            Request::UnwrapKey(req) if supported(req.mechanism) => todo!(),
            Request::Verify(req) if supported(req.mechanism) => todo!(),
            Request::WrapKey(req) if supported(req.mechanism) => todo!(),

            _ => return Err(trussed::Error::RequestNotAvailable),
        })
    }
}
