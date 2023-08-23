use core::fmt;
use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use hkdf::Hkdf;
use se05x::{
    se05x::{
        commands::{GetRandom, ReadObject, WriteBinary},
        ObjectId,
    },
    t1::I2CForT1,
};
use serde_byte_array::ByteArray;
use sha2::Sha256;
use trussed::{
    key::{Kind, Secrecy},
    platform::CryptoRng,
    serde_extensions::ExtensionImpl,
    service::{Filestore, Keystore, RngCore},
    types::{ui::Status, Location, PathBuf},
    Bytes,
};
use trussed_auth::{MAX_HW_KEY_LEN, MAX_PIN_LENGTH};

mod data;

use crate::{
    trussed_auth_impl::data::{expand_app_key, get_app_salt, PinData},
    Se050Backend, BACKEND_DIR,
};

pub const GLOBAL_SALT_ID: ObjectId = ObjectId(hex!("00000001"));
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const HASH_LEN: usize = 32;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) type Key = ByteArray<KEY_LEN>;
pub(crate) type Salt = ByteArray<SALT_LEN>;

#[derive(Clone)]
pub enum HardwareKey {
    None,
    Raw(Bytes<{ MAX_HW_KEY_LEN }>),
    Extracted(Hkdf<Sha256>),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NotFound,
    ReadFailed,
    WriteFailed,
    DeserializationFailed,
    SerializationFailed,
    BadPinType,
    Se050,
}

impl From<Error> for trussed::error::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::NotFound => Self::NoSuchKey,
            Error::ReadFailed => Self::FilesystemReadFailure,
            Error::WriteFailed => Self::FilesystemWriteFailure,
            Error::DeserializationFailed => Self::ImplementationError,
            Error::SerializationFailed => Self::ImplementationError,
            Error::BadPinType => Self::MechanismInvalid,
            Error::Se050 => Self::FunctionFailed,
        }
    }
}

impl From<se05x::se05x::Error> for Error {
    fn from(_value: se05x::se05x::Error) -> Self {
        Self::Se050
    }
}

impl fmt::Debug for HardwareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.debug_tuple("None").finish(),
            Self::Raw(_) => f.debug_tuple("Raw").field(&"[redacted]").finish(),
            Self::Extracted(_) => f.debug_tuple("Raw").field(&"[redacted]").finish(),
        }
    }
}

/// Per-client context for [`AuthBackend`][]
#[derive(Default, Debug)]
pub struct AuthContext {
    application_key: Option<Key>,
}

impl<Twi: I2CForT1, D: DelayUs<u32>> Se050Backend<Twi, D> {
    fn get_global_salt<R: CryptoRng + RngCore>(
        &self,
        global_fs: &mut impl Filestore,
        rng: &mut R,
    ) -> Result<Salt, Error> {
        let path = PathBuf::from("salt");
        global_fs
            .read(&path, self.metadata_location)
            .or_else(|_| {
                if global_fs.exists(&path, self.metadata_location) {
                    return Err(Error::ReadFailed);
                }

                let mut salt = Bytes::<SALT_LEN>::default();
                salt.resize_to_capacity();
                rng.fill_bytes(&mut salt);
                global_fs
                    .write(&path, self.metadata_location, &salt)
                    .or(Err(Error::WriteFailed))
                    .and(Ok(salt))
            })
            .and_then(|b| (**b).try_into().or(Err(Error::ReadFailed)))
    }

    fn get_se050_salt(&mut self) -> Result<Salt, Error> {
        let buf = &mut [0; 32];
        self.se.enable()?;
        match self.se.run_command(
            &ReadObject {
                object_id: GLOBAL_SALT_ID,
                offset: Some(0.into()),
                length: Some((SALT_LEN as u16).into()),
                rsa_key_component: None,
            },
            buf,
        ) {
            Ok(res) => return Ok(res.data.try_into().map_err(|_| Error::ReadFailed)?),
            Err(se05x::se05x::Error::Status(iso7816::Status::ConditionsOfUseNotSatisfied)) => {}
            Err(_err) => {
                debug!("Got unexpected error: {_err:?}");
                return Err(Error::Se050);
            }
        };

        // Salt was not found, need to generate, store it and return it.
        let salt: [u8; SALT_LEN] = self
            .se
            .run_command(
                &GetRandom {
                    length: (SALT_LEN as u16).into(),
                },
                buf,
            )?
            .data
            .try_into()
            .map_err(|_| Error::ReadFailed)?;

        self.se.run_command(
            &WriteBinary {
                transient: false,
                policy: None,
                object_id: GLOBAL_SALT_ID,
                offset: Some(0.into()),
                file_length: Some((SALT_LEN as u16).into()),
                data: Some(&salt),
            },
            buf,
        )?;

        Ok(salt.into())
    }

    fn extract<R: CryptoRng + RngCore>(
        &mut self,
        global_fs: &mut impl Filestore,
        ikm: Option<Bytes<MAX_HW_KEY_LEN>>,
        rng: &mut R,
    ) -> Result<&Hkdf<Sha256>, Error> {
        let ikm: &[u8] = ikm.as_deref().map(|i| &**i).unwrap_or(&[]);
        let salt = self.get_global_salt(global_fs, rng)?;
        let se050_salt = self.get_se050_salt()?;

        let mut real_ikm: Bytes<{ SALT_LEN + MAX_HW_KEY_LEN }> =
            Bytes::from_slice(&*se050_salt).unwrap();
        real_ikm.extend_from_slice(ikm).unwrap();

        let kdf = Hkdf::new(Some(&*salt), &real_ikm);
        self.hw_key = HardwareKey::Extracted(kdf);
        match &self.hw_key {
            HardwareKey::Extracted(kdf) => Ok(kdf),
            // hw_key was just set to Extracted
            _ => unreachable!(),
        }
    }

    fn expand(kdf: &Hkdf<Sha256>, client_id: &PathBuf) -> Key {
        let mut out = Key::default();
        #[allow(clippy::expect_used)]
        kdf.expand(client_id.as_ref().as_bytes(), &mut *out)
            .expect("Out data is always valid");
        out
    }

    fn generate_app_key<R: CryptoRng + RngCore>(
        &mut self,
        client_id: PathBuf,
        global_fs: &mut impl Filestore,
        rng: &mut R,
    ) -> Result<Key, Error> {
        Ok(match &self.hw_key {
            HardwareKey::Extracted(okm) => Self::expand(okm, &client_id),
            HardwareKey::Raw(hw_k) => {
                let kdf = self.extract(global_fs, Some(hw_k.clone()), rng)?;
                Self::expand(kdf, &client_id)
            }
            HardwareKey::None => {
                let kdf = self.extract(global_fs, None, rng)?;
                Self::expand(kdf, &client_id)
            }
        })
    }

    fn get_app_key<R: CryptoRng + RngCore>(
        &mut self,
        client_id: PathBuf,
        global_fs: &mut impl Filestore,
        ctx: &mut AuthContext,
        rng: &mut R,
    ) -> Result<Key, Error> {
        if let Some(app_key) = ctx.application_key {
            return Ok(app_key);
        }

        let app_key = self.generate_app_key(client_id, global_fs, rng)?;
        ctx.application_key = Some(app_key);
        Ok(app_key)
    }
}

impl<Twi: I2CForT1, D: DelayUs<u32>> ExtensionImpl<trussed_auth::AuthExtension>
    for Se050Backend<Twi, D>
{
    fn extension_request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut trussed::types::CoreContext,
        backend_ctx: &mut Self::Context,
        request: &<trussed_auth::AuthExtension as trussed::serde_extensions::Extension>::Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<
        <trussed_auth::AuthExtension as trussed::serde_extensions::Extension>::Reply,
        trussed::Error,
    > {
        // FIXME: Have a real implementation from trussed
        let mut backend_path = core_ctx.path.clone();
        backend_path.push(&PathBuf::from(BACKEND_DIR));
        let fs = &mut resources.filestore(backend_path);
        let global_fs = &mut resources.filestore(PathBuf::from(BACKEND_DIR));
        let rng = &mut resources.rng()?;
        let client_id = core_ctx.path.clone();
        let keystore = &mut resources.keystore(core_ctx)?;

        use trussed_auth::{reply, AuthRequest};
        match request {
            AuthRequest::HasPin(request) => {
                let has_pin = fs.exists(&request.id.path(), self.metadata_location);
                Ok(reply::HasPin { has_pin }.into())
            }
            AuthRequest::CheckPin(request) => {
                let pin_data = PinData::load(request.id, fs, self.metadata_location)?;
                let app_key = self.get_app_key(client_id, global_fs, &mut backend_ctx.auth, rng)?;
                let success = pin_data.check(&request.pin, &app_key, &mut self.se, rng)?;
                Ok(reply::CheckPin { success }.into())
            }
            AuthRequest::GetPinKey(request) => {
                let pin_data = PinData::load(request.id, fs, self.metadata_location)?;
                let app_key = self.get_app_key(client_id, global_fs, &mut backend_ctx.auth, rng)?;
                let key = pin_data.check_and_get_key(&request.pin, &app_key, &mut self.se, rng)?;
                let Some(material) = key else {
                    return Ok(reply::GetPinKey{result: None}.into());
                };
                let key_id = keystore.store_key(
                    Location::Volatile,
                    Secrecy::Secret,
                    Kind::Symmetric(32),
                    &*material,
                )?;
                Ok(reply::GetPinKey {
                    result: Some(key_id),
                }
                .into())
            }
            AuthRequest::GetApplicationKey(request) => {
                let salt = get_app_salt(fs, rng, self.metadata_location)?;
                let key = expand_app_key(
                    &salt,
                    &self.get_app_key(client_id, global_fs, &mut backend_ctx.auth, rng)?,
                    &request.info,
                );
                let key_id = keystore.store_key(
                    Location::Volatile,
                    Secrecy::Secret,
                    Kind::Symmetric(KEY_LEN),
                    &*key,
                )?;
                Ok(reply::GetApplicationKey { key: key_id }.into())
            }
            AuthRequest::SetPin(request) => {
                if fs.exists(&request.id.path(), self.metadata_location) {
                    return Err(trussed::Error::FunctionFailed);
                }
                let pin = PinData::new(request.id, rng, request.derive_key);
                let app_key = self.get_app_key(client_id, global_fs, &mut backend_ctx.auth, rng)?;
                pin.create(
                    fs,
                    self.metadata_location,
                    &mut self.se,
                    &app_key,
                    &request.pin,
                    request.retries,
                )?;
                Ok(reply::SetPin {}.into())
            }
            AuthRequest::SetPinWithKey(request) => {
                if fs.exists(&request.id.path(), self.metadata_location) {
                    return Err(trussed::Error::FunctionFailed);
                }
                let app_key = self.get_app_key(client_id, global_fs, &mut backend_ctx.auth, rng)?;
                let key =
                    keystore.load_key(Secrecy::Secret, Some(Kind::Symmetric(32)), &request.key)?;
                let key: Key = (&*key.material)
                    .try_into()
                    .map_err(|_| Error::DeserializationFailed)?;

                PinData::create_with_key(
                    request.id,
                    fs,
                    self.metadata_location,
                    &mut self.se,
                    &app_key,
                    &request.pin,
                    request.retries,
                    rng,
                    &key,
                )?;
                Ok(reply::SetPinWithKey {}.into())
            }
            AuthRequest::ChangePin(request) => {
                let mut pin_data = PinData::load(request.id, fs, self.metadata_location)?;
                let app_key = self.get_app_key(client_id, global_fs, &mut backend_ctx.auth, rng)?;
                let success = pin_data.update(
                    &mut self.se,
                    &app_key,
                    &request.old_pin,
                    &request.new_pin,
                    fs,
                    self.metadata_location,
                    rng,
                )?;
                Ok(reply::ChangePin { success }.into())
            }
            AuthRequest::DeletePin(_req) => Err(trussed::Error::FunctionNotSupported),
            AuthRequest::DeleteAllPins(_req) => Err(trussed::Error::FunctionNotSupported),
            AuthRequest::PinRetries(_req) => Err(trussed::Error::FunctionNotSupported),
            AuthRequest::ResetAppKeys(_req) => Err(trussed::Error::FunctionNotSupported),
            AuthRequest::ResetAuthData(_req) => Err(trussed::Error::FunctionNotSupported),
        }
    }
}
