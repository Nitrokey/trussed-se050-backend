use core::fmt;
use hkdf::Hkdf;
use littlefs2_core::{path, Path};
use se05x::{
    embedded_hal::Delay,
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
    service::{Filestore, Keystore, RngCore, ServiceResources},
    types::{Location, PathBuf},
    Bytes,
};
use trussed_auth_backend::MAX_HW_KEY_LEN;

pub(crate) mod data;

use crate::{
    namespacing::{namespace, NamespaceValue, ObjectKind},
    trussed_auth_impl::data::{
        delete_all_pins, delete_app_salt, expand_app_key, get_app_salt, PinData,
    },
    Se050Backend, BACKEND_DIR,
};

pub const GLOBAL_SALT_ID: ObjectId = ObjectId([
    0,
    0,
    0,
    namespace(NamespaceValue::NoClient, ObjectKind::SaltValue),
]);

pub(crate) const SALT_LEN: usize = 16;
pub(crate) const HASH_LEN: usize = 32;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) type Key = ByteArray<KEY_LEN>;
pub(crate) type Salt = ByteArray<SALT_LEN>;

pub(crate) const AUTH_DIR: &Path = path!("auth");

#[derive(Clone)]
pub enum HardwareKey {
    None,
    Raw(Bytes<{ MAX_HW_KEY_LEN }>),
    Extracted(Hkdf<Sha256>),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    _NotFound,
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
            Error::_NotFound => Self::NoSuchKey,
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

/// Per-client context for the auth extension implementation
#[derive(Default, Debug)]
pub struct AuthContext {
    application_key: Option<Key>,
}

impl<Twi: I2CForT1, D: Delay> Se050Backend<Twi, D> {
    fn get_global_salt<R: CryptoRng + RngCore>(
        &self,
        global_fs: &mut impl Filestore,
        rng: &mut R,
    ) -> Result<Salt, Error> {
        let path = path!("salt");
        global_fs
            .read(path, self.metadata_location)
            .or_else(|_| {
                if global_fs.exists(path, self.metadata_location) {
                    return Err(Error::ReadFailed);
                }

                let mut salt = Bytes::<SALT_LEN>::default();
                salt.resize_to_capacity();
                rng.fill_bytes(&mut salt);
                global_fs
                    .write(path, self.metadata_location, &salt)
                    .or(Err(Error::WriteFailed))
                    .and(Ok(salt))
            })
            .and_then(|b| (**b).try_into().or(Err(Error::ReadFailed)))
    }

    fn get_se050_salt(&mut self) -> Result<Salt, Error> {
        let buf = &mut [0; 32];
        debug!("Attempting to read");
        let tmp = self.se.run_command(
            &ReadObject::builder()
                .object_id(GLOBAL_SALT_ID)
                .length((SALT_LEN as u16).into())
                .build(),
            buf,
        );
        match tmp {
            Ok(res) => return res.data.try_into().map_err(|_| Error::ReadFailed),
            Err(se05x::se05x::Error::Status(iso7816::Status::IncorrectDataParameter)) => {}
            Err(_err) => {
                error!("Got unexpected error: {_err:?}");
                return Err(Error::Se050);
            }
        };

        debug!("Generating salt");
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
            .map_err(|_err| {
                error!("Random data failed: {_err:?}");
                Error::ReadFailed
            })?;

        debug!("Writing salt");
        self.se
            .run_command(
                &WriteBinary::builder()
                    .object_id(GLOBAL_SALT_ID)
                    .offset(0.into())
                    .file_length((SALT_LEN as u16).into())
                    .data(&salt)
                    .build(),
                buf,
            )
            .map_err(|_err| {
                error!("Writing data failed: {_err:?}");
                Error::ReadFailed
            })?;

        Ok(salt.into())
    }

    fn extract<R: CryptoRng + RngCore>(
        &mut self,
        global_fs: &mut impl Filestore,
        ikm: Option<Bytes<MAX_HW_KEY_LEN>>,
        rng: &mut R,
    ) -> Result<&Hkdf<Sha256>, Error> {
        debug!("Extracting key");
        let ikm: &[u8] = ikm.as_deref().map(|i| &**i).unwrap_or(&[]);
        let salt = self.get_global_salt(global_fs, rng)?;
        debug!("Getting se050 salt");
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

    fn expand(kdf: &Hkdf<Sha256>, client_id: &Path) -> Key {
        let mut out = Key::default();
        #[allow(clippy::expect_used)]
        kdf.expand(client_id.as_ref().as_bytes(), &mut *out)
            .map_err(|_err| {
                error_now!("Out data is always valid: {_err:?}");
            })
            .unwrap();
        out
    }

    fn generate_app_key<R: CryptoRng + RngCore>(
        &mut self,
        client_id: &Path,
        global_fs: &mut impl Filestore,
        rng: &mut R,
    ) -> Result<Key, Error> {
        debug!("Generating app key");
        Ok(match &self.hw_key {
            HardwareKey::Extracted(okm) => Self::expand(okm, client_id),
            HardwareKey::Raw(hw_k) => {
                let kdf = self.extract(global_fs, Some(hw_k.clone()), rng)?;
                Self::expand(kdf, client_id)
            }
            HardwareKey::None => {
                let kdf = self.extract(global_fs, None, rng)?;
                Self::expand(kdf, client_id)
            }
        })
    }

    fn get_app_key<R: CryptoRng + RngCore>(
        &mut self,
        client_id: &Path,
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

impl<Twi: I2CForT1, D: Delay> ExtensionImpl<trussed_auth::AuthExtension> for Se050Backend<Twi, D> {
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
        self.configure()?;
        let backend_ctx = backend_ctx.with_namespace(&self.ns, &core_ctx.path);
        let auth_ctx = backend_ctx.auth;
        let ns = backend_ctx.ns;

        debug!("Trussed Auth request: {request:?}");
        // FIXME: Have a real implementation from trussed
        let mut backend_path = core_ctx.path.clone();
        backend_path.push(BACKEND_DIR);
        backend_path.push(AUTH_DIR);

        /// Coerce an FnMut into a FnOnce to ensure the stores are not created twice by mistake
        fn once<R, P>(
            generator: impl FnOnce(&mut ServiceResources<P>) -> R,
        ) -> impl FnOnce(&mut ServiceResources<P>) -> R {
            generator
        }

        let fs = once(|resources| match self.layout {
            crate::FilesystemLayout::V0 => resources.filestore(backend_path),
            crate::FilesystemLayout::V1 => resources.raw_filestore(backend_path),
        });
        let global_fs = once(|resources| match self.layout {
            crate::FilesystemLayout::V0 => resources.filestore(PathBuf::from(BACKEND_DIR)),
            crate::FilesystemLayout::V1 => resources.raw_filestore(PathBuf::from(BACKEND_DIR)),
        });
        let client_id = &core_ctx.path;
        let keystore = once(|resources| resources.keystore(core_ctx.path.clone()));

        use trussed_auth::{reply, request, AuthRequest};
        match request {
            AuthRequest::HasPin(request) => {
                let fs = &mut fs(resources);
                let has_pin = fs.exists(&request.id.path(), self.metadata_location);
                Ok(reply::HasPin { has_pin }.into())
            }
            AuthRequest::CheckPin(request) => {
                let keystore = &mut keystore(resources)?;
                let global_fs = &mut global_fs(resources);

                let pin_data =
                    PinData::load(request.id, &mut fs(resources), self.metadata_location)?;
                let app_key = self.get_app_key(client_id, global_fs, auth_ctx, keystore.rng())?;
                let success =
                    pin_data.check(&request.pin, &app_key, &mut self.se, keystore.rng())?;
                Ok(reply::CheckPin { success }.into())
            }
            AuthRequest::GetPinKey(request) => {
                let fs = &mut fs(resources);
                let global_fs = &mut global_fs(resources);
                let keystore = &mut keystore(resources)?;

                let pin_data =
                    PinData::load(request.id, fs, self.metadata_location).inspect_err(|_err| {
                        debug!("Failed to get pin data: {_err:?}");
                    })?;
                let app_key = self.get_app_key(client_id, global_fs, auth_ctx, keystore.rng())?;
                let key = pin_data.check_and_get_key(
                    &request.pin,
                    &app_key,
                    &mut self.se,
                    keystore.rng(),
                )?;
                let Some(material) = key else {
                    return Ok(reply::GetPinKey { result: None }.into());
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
                let keystore = &mut keystore(resources)?;
                let global_fs = &mut global_fs(resources);
                let fs = &mut fs(resources);

                let salt = get_app_salt(fs, keystore.rng(), self.metadata_location)?;
                let key = expand_app_key(
                    &salt,
                    &self.get_app_key(client_id, global_fs, auth_ctx, keystore.rng())?,
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
                let keystore = &mut keystore(resources)?;
                let global_fs = &mut global_fs(resources);
                let fs = &mut fs(resources);

                if fs.exists(&request.id.path(), self.metadata_location) {
                    return Err(trussed::Error::FunctionFailed);
                }
                let pin = PinData::new(request.id, ns, keystore.rng(), request.derive_key);
                let app_key = self.get_app_key(client_id, global_fs, auth_ctx, keystore.rng())?;
                pin.create(
                    fs,
                    self.metadata_location,
                    &mut self.se,
                    &app_key,
                    &request.pin,
                    request.retries,
                )?;
                debug!("Created pin");
                Ok(reply::SetPin {}.into())
            }
            AuthRequest::SetPinWithKey(request) => {
                let keystore = &mut keystore(resources)?;
                let global_fs = &mut global_fs(resources);
                let fs = &mut fs(resources);

                let app_key = self.get_app_key(client_id, global_fs, auth_ctx, keystore.rng())?;
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
                    keystore.rng(),
                    &key,
                    ns,
                )?;
                Ok(reply::SetPinWithKey {}.into())
            }
            AuthRequest::ChangePin(request) => {
                let global_fs = &mut global_fs(resources);
                let fs = &mut fs(resources);
                let keystore = &mut keystore(resources)?;

                let mut pin_data = PinData::load(request.id, fs, self.metadata_location)?;
                let app_key = self.get_app_key(client_id, global_fs, auth_ctx, keystore.rng())?;
                let success = pin_data.update(
                    &mut self.se,
                    &app_key,
                    request,
                    fs,
                    self.metadata_location,
                    keystore.rng(),
                )?;
                Ok(reply::ChangePin { success }.into())
            }
            AuthRequest::DeletePin(request) => {
                let fs = &mut fs(resources);

                let pin_data = PinData::load(request.id, fs, self.metadata_location)?;
                pin_data.delete(fs, self.metadata_location, &mut self.se)?;
                Ok(reply::DeletePin {}.into())
            }
            AuthRequest::DeleteAllPins(request::DeleteAllPins) => {
                use crate::core_api::ItemsToDelete;
                let fs = &mut fs(resources);
                // Satisfy the borrow checker
                // The `once` trick makes it loose the information that drop is a noop :/
                drop(global_fs);

                delete_all_pins(fs, self.metadata_location, &mut self.se)?;

                // Ensure that any remaining PIN for the application is also deleted
                self.delete_all_items(ItemsToDelete::PINS, &[], ns)?;
                Ok(reply::DeleteAllPins.into())
            }
            AuthRequest::PinRetries(request) => {
                let fs = &mut fs(resources);
                let keystore = &mut keystore(resources)?;

                debug!("Getting pin retries");
                let pin_data = PinData::load(request.id, fs, self.metadata_location)?;
                debug!("Loaded {pin_data:?}");
                let (attempts, max) = pin_data.get_attempts(&mut self.se, keystore.rng())?;
                debug!("Attempts: {attempts:?}, {max:?}");
                Ok(reply::PinRetries {
                    retries: Some((max - attempts) as u8),
                }
                .into())
            }
            AuthRequest::ResetAppKeys(_req) => {
                let fs = &mut fs(resources);

                delete_app_salt(fs, self.metadata_location)?;
                Ok(reply::ResetAppKeys.into())
            }
            AuthRequest::ResetAuthData(_req) => {
                let fs = &mut fs(resources);

                delete_app_salt(fs, self.metadata_location)?;
                delete_all_pins(fs, self.metadata_location, &mut self.se)?;
                Ok(reply::ResetAuthData.into())
            }
        }
    }
}
