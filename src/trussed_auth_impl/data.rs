use crate::{
    namespacing::{NamespaceValue, PinObjectId, PinObjectIdWithDerived},
    trussed_auth_impl::KEY_LEN,
    GLOBAL_ATTEST_ID,
};

use super::{Error, Key, Salt, HASH_LEN, SALT_LEN};

use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use hmac::{Hmac, Mac};
use littlefs2::path;
use rand::Rng;
use se05x::{
    se05x::{
        commands::{
            CheckObjectExists, CloseSession, CreateSession, DeleteSecureObject, GetRandom,
            ReadAttestObject, ReadObject, VerifySessionUserId, WriteBinary, WriteSymmKey,
            WriteUserId,
        },
        policies::{ObjectAccessRule, ObjectPolicyFlags, Policy, PolicySet},
        AttestationAlgo, ObjectId, Se05X, Se05XResult, SymmKeyType,
    },
    t1::I2CForT1,
};
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use sha2::Sha256;
use trussed::{
    api::NotBefore,
    platform::CryptoRng,
    service::{Filestore, RngCore},
    types::{Bytes, Location, Path, PathBuf},
};
use trussed_auth::{request, PinId, MAX_PIN_LENGTH};

#[derive(Serialize, Deserialize, Debug, Clone)]
enum PinSeId {
    Raw(PinObjectId),
    WithDerived(PinObjectIdWithDerived),
}

impl PinSeId {
    fn pin_id(&self) -> ObjectId {
        match self {
            PinSeId::Raw(i) => i.0,
            PinSeId::WithDerived(i) => i.pin_id(),
        }
    }
}

fn app_salt_path() -> PathBuf {
    const SALT_PATH: &str = "application_salt";

    PathBuf::from(SALT_PATH)
}

pub(crate) fn get_app_salt<S: Filestore, R: CryptoRng + RngCore>(
    fs: &mut S,
    rng: &mut R,
    location: Location,
) -> Result<Salt, Error> {
    if !fs.exists(&app_salt_path(), location) {
        create_app_salt(fs, rng, location)
    } else {
        load_app_salt(fs, location)
    }
}

pub(crate) fn delete_app_salt<S: Filestore>(
    fs: &mut S,
    location: Location,
) -> Result<(), trussed::Error> {
    if fs.exists(&app_salt_path(), location) {
        fs.remove_file(&app_salt_path(), location)
    } else {
        Ok(())
    }
}

fn create_app_salt<S: Filestore, R: CryptoRng + RngCore>(
    fs: &mut S,
    rng: &mut R,
    location: Location,
) -> Result<Salt, Error> {
    let mut salt = Salt::default();
    rng.fill_bytes(&mut *salt);
    fs.write(&app_salt_path(), location, &*salt)
        .map_err(|_| Error::WriteFailed)?;
    Ok(salt)
}

fn load_app_salt<S: Filestore>(fs: &mut S, location: Location) -> Result<Salt, Error> {
    fs.read(&app_salt_path(), location)
        .map_err(|_| Error::ReadFailed)
        .and_then(|b: Bytes<SALT_LEN>| (**b).try_into().map_err(|_| Error::ReadFailed))
}

pub fn expand_app_key(salt: &Salt, application_key: &Key, info: &[u8]) -> Key {
    #[allow(clippy::expect_used)]
    let mut hmac = Hmac::<Sha256>::new_from_slice(&**application_key)
        .expect("Slice will always be of acceptable size");
    hmac.update(&**salt);
    hmac.update(&(info.len() as u64).to_be_bytes());
    hmac.update(info);
    let tmp: [_; HASH_LEN] = hmac.finalize().into_bytes().into();
    tmp.into()
}

const PIN_KEY_LEN: usize = 16;
type PinKey = ByteArray<PIN_KEY_LEN>;

fn pin_len(pin: &[u8]) -> u8 {
    const _: () = assert!(MAX_PIN_LENGTH <= u8::MAX as usize);
    pin.len() as u8
}

pub fn expand_pin_key(salt: &Salt, application_key: &Key, id: PinId, pin: &[u8]) -> PinKey {
    #[allow(clippy::expect_used)]
    let mut hmac = Hmac::<Sha256>::new_from_slice(&**application_key)
        .expect("Slice will always be of acceptable size");
    hmac.update(&[u8::from(id)]);
    hmac.update(&[pin_len(pin)]);
    hmac.update(pin);
    hmac.update(&**salt);
    let tmp: [_; HASH_LEN] = hmac.finalize().into_bytes().into();
    PinKey::new(tmp[..PIN_KEY_LEN].try_into().unwrap())
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PinData {
    #[serde(skip)]
    id: PinId,
    salt: Salt,
    /// Id of the AES key authentication object for the PIN
    se_id: PinSeId,
}

fn simple_pin_policy(pin_aes_key_id: ObjectId) -> [Policy; 2] {
    [
        Policy {
            object_id: pin_aes_key_id,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_WRITE),
        },
        Policy {
            object_id: ObjectId::INVALID,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_DELETE),
        },
    ]
}

fn pin_policy_with_key(pin_aes_key_id: ObjectId, protected_key_id: ObjectId) -> [Policy; 2] {
    [
        Policy {
            object_id: pin_aes_key_id,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_WRITE),
        },
        Policy {
            object_id: protected_key_id,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_DELETE),
        },
    ]
}

fn key_policy(pin_aes_key_id: ObjectId) -> [Policy; 2] {
    [
        Policy {
            object_id: pin_aes_key_id,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_READ),
        },
        Policy {
            object_id: ObjectId::INVALID,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_DELETE),
        },
    ]
}

impl PinData {
    pub fn new<R: RngCore + CryptoRng>(
        id: PinId,
        ns: NamespaceValue,
        rng: &mut R,
        derived_key: bool,
    ) -> Self {
        let salt = ByteArray::new(rng.gen());
        let se_id = match derived_key {
            true => PinSeId::WithDerived(PinObjectIdWithDerived::new(rng, ns)),
            false => PinSeId::Raw(PinObjectId::new(rng, ns)),
        };
        Self { id, salt, se_id }
    }

    pub fn save(&self, fs: &mut impl Filestore, location: Location) -> Result<(), Error> {
        let data = trussed::cbor_serialize_bytes::<_, 256>(&self)
            .map_err(|_| Error::SerializationFailed)?;
        fs.write(&self.id.path(), location, &data)
            .map_err(|_| Error::WriteFailed)?;
        Ok(())
    }

    // Write the necessary objects to the SE050
    pub fn create<Twi: I2CForT1, D: DelayUs<u32>>(
        &self,
        fs: &mut impl Filestore,
        location: Location,
        se050: &mut Se05X<Twi, D>,
        app_key: &Key,
        value: &[u8],
        retries: Option<u8>,
    ) -> Result<(), Error> {
        self.save(fs, location)?;

        let buf = &mut [0; 128];
        let pin_aes_key_value = expand_pin_key(&self.salt, app_key, self.id, value);

        let pin_aes_key_policy;
        // So that temporary arrays are scoped to the function to please the borrow checker
        let (tmp1, tmp2);
        match self.se_id {
            PinSeId::WithDerived(se_id) => {
                tmp1 = pin_policy_with_key(se_id.pin_id(), se_id.protected_key_id());
                pin_aes_key_policy = &tmp1;

                let protected_key_policy = &key_policy(se_id.pin_id());
                let key = se050.run_command(
                    &GetRandom {
                        length: (KEY_LEN as u16).into(),
                    },
                    buf,
                )?;
                let key: Key = ByteArray::new(key.data.try_into().map_err(|_| Error::Se050)?);
                se050.run_command(
                    &WriteBinary::builder()
                        .object_id(se_id.protected_key_id())
                        .policy(PolicySet(protected_key_policy))
                        .offset(0.into())
                        .file_length((KEY_LEN as u16).into())
                        .data(&*key)
                        .build(),
                    buf,
                )?;
            }
            PinSeId::Raw(se_id) => {
                tmp2 = simple_pin_policy(se_id.0);
                pin_aes_key_policy = &tmp2;
            }
        }
        let write = WriteSymmKey::builder()
            .is_auth(true)
            .key_type(SymmKeyType::Aes)
            .policy(PolicySet(pin_aes_key_policy))
            .object_id(self.se_id.pin_id())
            .value(&*pin_aes_key_value);
        let write = match retries {
            None => write.build(),
            Some(v) => write.max_attempts((v as u16).into()).build(),
        };
        se050.run_command(&write, buf)?;
        Ok(())
    }

    // Write the necessary objects to the SE050
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_key<Twi: I2CForT1, D: DelayUs<u32>, R: RngCore + CryptoRng>(
        id: PinId,
        fs: &mut impl Filestore,
        location: Location,
        se050: &mut Se05X<Twi, D>,
        app_key: &Key,
        value: &[u8],
        retries: Option<u8>,
        rng: &mut R,
        key: &Key,
        ns: NamespaceValue,
    ) -> Result<Self, Error> {
        let this = Self::new(id, ns, rng, true);
        this.save(fs, location)?;

        let PinSeId::WithDerived(se_id) = this.se_id else {
            unreachable!()
        };

        let buf = &mut [0; 128];
        let pin_aes_key_value = expand_pin_key(&this.salt, app_key, this.id, value);

        let protected_key_id = se_id.protected_key_id();

        let pin_aes_key_policy = &pin_policy_with_key(se_id.pin_id(), protected_key_id);

        let protected_key_policy = &key_policy(se_id.pin_id());
        se050.run_command(
            &WriteBinary::builder()
                .object_id(protected_key_id)
                .policy(PolicySet(protected_key_policy))
                .offset(0.into())
                .file_length((KEY_LEN as u16).into())
                .data(&**key)
                .build(),
            buf,
        )?;

        let write = WriteSymmKey::builder()
            .is_auth(true)
            .key_type(SymmKeyType::Aes)
            .policy(PolicySet(pin_aes_key_policy))
            .object_id(se_id.pin_id())
            .value(&*pin_aes_key_value);
        let write = match retries {
            None => write.build(),
            Some(v) => write.max_attempts((v as u16).into()).build(),
        };
        se050.run_command(&write, buf)?;
        Ok(this)
    }

    pub fn check<Twi: I2CForT1, D: DelayUs<u32>, R: RngCore + CryptoRng>(
        &self,
        value: &[u8],
        app_key: &Key,
        se050: &mut Se05X<Twi, D>,
        rng: &mut R,
    ) -> Result<bool, Error> {
        debug!("Checking pin: {:?}", self.id);
        let buf = &mut [0; 1024];
        let pin_aes_key_value = expand_pin_key(&self.salt, app_key, self.id, value);
        let res = se050.run_command(
            &CreateSession {
                object_id: self.se_id.pin_id(),
            },
            buf,
        )?;
        let session_id = res.session_id;
        let res = se050
            .authenticate_aes128_session(session_id, &pin_aes_key_value, rng)
            .map_err(|err| {
                error!("Failed to authenticate pin: {err:?}");
                err
            })?;
        se050
            .run_session_command(session_id, &CloseSession {}, buf)
            .map_err(|err| {
                error!("Failed to close session: {err:?}");
                err
            })?;
        debug!("Check succeeded with {res:?}");
        Ok(res)
    }

    pub fn check_and_get_key<Twi: I2CForT1, D: DelayUs<u32>, R: RngCore + CryptoRng>(
        &self,
        value: &[u8],
        app_key: &Key,
        se050: &mut Se05X<Twi, D>,
        rng: &mut R,
    ) -> Result<Option<Key>, Error> {
        let PinSeId::WithDerived(se_id) = self.se_id else {
            return Err(Error::BadPinType);
        };

        let buf = &mut [0; 1024];
        let pin_aes_key_value = expand_pin_key(&self.salt, app_key, self.id, value);
        let res = se050.run_command(
            &CreateSession {
                object_id: se_id.pin_id(),
            },
            buf,
        )?;
        let session_id = res.session_id;
        let res = match se050.authenticate_aes128_session(session_id, &pin_aes_key_value, rng) {
            Ok(true) => {
                let key = se050.run_session_command(
                    session_id,
                    &ReadObject::builder()
                        .object_id(se_id.protected_key_id())
                        .length((KEY_LEN as u16).into())
                        .build(),
                    buf,
                )?;
                Ok(Some(
                    key.data
                        .try_into()
                        .map_err(|_| Error::DeserializationFailed)?,
                ))
            }
            Ok(false) => Ok(None),
            Err(err) => Err(err.into()),
        };
        se050.run_session_command(session_id, &CloseSession {}, buf)?;
        res
    }

    pub fn update<Twi: I2CForT1, D: DelayUs<u32>, R: RngCore + CryptoRng>(
        &mut self,
        se050: &mut Se05X<Twi, D>,
        app_key: &Key,
        request: &request::ChangePin,
        fs: &mut impl Filestore,
        location: Location,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let buf = &mut [0; 1024];
        let pin_aes_key_value = expand_pin_key(&self.salt, app_key, self.id, &request.old_pin);
        let res = se050.run_command(
            &CreateSession {
                object_id: self.se_id.pin_id(),
            },
            buf,
        )?;
        let session_id = res.session_id;
        let res = se050.authenticate_aes128_session(session_id, &pin_aes_key_value, rng)?;

        self.salt = ByteArray::new(rng.gen());
        let new_pin_aes_key_value = expand_pin_key(&self.salt, app_key, self.id, &request.new_pin);
        se050.run_session_command(
            session_id,
            &WriteSymmKey::builder()
                .is_auth(true)
                .key_type(SymmKeyType::Aes)
                .object_id(self.se_id.pin_id())
                .value(&*new_pin_aes_key_value)
                .build(),
            buf,
        )?;
        self.save(fs, location)?;
        se050.run_session_command(session_id, &CloseSession {}, buf)?;
        Ok(res)
    }

    pub fn load(id: PinId, fs: &mut impl Filestore, location: Location) -> Result<Self, Error> {
        // let data = trussed::cbor_serialize_bytes::<_, 256>(&self)
        //     .map_err(|_| Error::SerializationFailed)?;
        let data = fs
            .read::<1024>(&id.path(), location)
            .map_err(|_| Error::ReadFailed)?;
        let this = trussed::cbor_deserialize(&data).map_err(|_| Error::DeserializationFailed)?;
        Ok(Self { id, ..this })
    }

    pub fn delete_with_derived<Twi: I2CForT1, D: DelayUs<u32>>(
        se050: &mut Se05X<Twi, D>,
        se_id: PinObjectIdWithDerived,
    ) -> Result<u16, Error> {
        let mut count = 0;
        let buf = &mut [0; 1024];
        debug!("checking existence");
        let exists = se050
            .run_command(
                &CheckObjectExists {
                    object_id: se_id.protected_key_id(),
                },
                buf,
            )
            .map_err(|_err| {
                debug!("Failed existence check: {_err:?}");
                _err
            })?
            .result;
        if exists == Se05XResult::Success {
            debug!("Deleting key");
            se050
                .run_command(
                    &DeleteSecureObject {
                        object_id: se_id.protected_key_id(),
                    },
                    buf,
                )
                .map_err(|_err| {
                    debug!("Failed deletion: {_err:?}");
                    _err
                })?;
            count += 1;
        }

        let exists = se050
            .run_command(
                &CheckObjectExists {
                    object_id: se_id.pin_id(),
                },
                buf,
            )
            .map_err(|_err| {
                error!("Failed existence check: {_err:?}");
                Error::ReadFailed
            })?
            .result
            .is_success();
        if !exists {
            return Ok(count);
        }

        debug!("Writing userid ");
        se050.run_command(
            &WriteUserId::builder()
                .object_id(se_id.protected_key_id())
                .data(&hex!("01020304"))
                .policy(PolicySet(&[Policy {
                    object_id: ObjectId::INVALID,
                    access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_DELETE),
                }]))
                .build(),
            buf,
        )?;
        debug!("Creating session");
        let session_id = se050
            .run_command(
                &CreateSession {
                    object_id: se_id.protected_key_id(),
                },
                buf,
            )?
            .session_id;
        debug!("Auth session");
        se050.run_session_command(
            session_id,
            &VerifySessionUserId {
                user_id: &hex!("01020304"),
            },
            buf,
        )?;
        debug!("Deleting auth");
        se050
            .run_session_command(
                session_id,
                &DeleteSecureObject {
                    object_id: se_id.pin_id(),
                },
                buf,
            )
            .map_err(|_err| {
                error!("Failed to delete auth: {_err:?}");
                _err
            })?;
        debug!("Closing sess");
        se050.run_session_command(session_id, &CloseSession {}, buf)?;
        debug!("Deleting userid");
        se050
            .run_command(
                &DeleteSecureObject {
                    object_id: se_id.protected_key_id(),
                },
                buf,
            )
            .map_err(|err| {
                error!("Failed to delete user id: {err:?}");
                err
            })?;
        count += 1;
        Ok(count)
    }

    pub fn delete<Twi: I2CForT1, D: DelayUs<u32>>(
        self,
        fs: &mut impl Filestore,
        location: Location,
        se050: &mut Se05X<Twi, D>,
    ) -> Result<u16, Error> {
        debug!("Deleting {self:02x?}");
        let deleted_count = match self.se_id {
            PinSeId::WithDerived(se_id) => Self::delete_with_derived(se050, se_id)?,
            PinSeId::Raw(se_id) => {
                let buf = &mut [0; 1024];
                debug!("Deleting simple");
                se050.run_command(&DeleteSecureObject { object_id: se_id.0 }, buf)?;
                1
            }
        };

        debug!("Removing file {}", self.id.path());
        fs.remove_file(&self.id.path(), location).map_err(|_err| {
            error!("Removing file failed: {_err:?}");
            Error::WriteFailed
        })?;
        Ok(deleted_count)
    }

    /// Returns (tried, max)
    pub fn get_attempts<Twi: I2CForT1, D: DelayUs<u32>, R: RngCore + CryptoRng>(
        self,
        se050: &mut Se05X<Twi, D>,
        rng: &mut R,
    ) -> Result<(u16, u16), Error> {
        let buf = &mut [0u8; 1024];
        let attrs = se050
            .run_command(
                &ReadAttestObject::builder()
                    .object_id(self.se_id.pin_id())
                    .attestation_object(GLOBAL_ATTEST_ID)
                    .attestation_algo(AttestationAlgo::ECdsaSha512)
                    .freshness_random(&rng.gen())
                    .build(),
                buf,
            )
            .map_err(|err| {
                error!("Got err reading attempts: {err:?}");
                err
            })?
            .attributes;
        let max = attrs.max_authentication_attempts();
        let attempts = attrs.authentication_attempts_counter();
        Ok((attempts, max))
    }
}

fn delete_from_path<Twi: I2CForT1, D: DelayUs<u32>>(
    path: &Path,
    fs: &mut impl Filestore,
    location: Location,
    se050: &mut Se05X<Twi, D>,
) -> Result<(), Error> {
    debug!("Deleting {path:?}");
    let path = path
        .as_ref()
        .strip_prefix(path.parent().as_deref().map(AsRef::as_ref).unwrap_or(""))
        .and_then(|path| path.strip_prefix('/'))
        .unwrap_or(path.as_ref());
    debug!("Deleting stripped: {path:?}");
    let id = path.parse().map_err(|_err| {
        debug!("Parsing name failed: {_err:?}");
        Error::DeserializationFailed
    })?;
    let pin = PinData::load(id, fs, location).map_err(|_err| {
        debug!("Failed  loading: {_err:?}");
        _err
    })?;
    pin.delete(fs, location, se050)?;
    Ok(())
}

pub(crate) fn delete_all_pins<Twi: I2CForT1, D: DelayUs<u32>>(
    fs: &mut impl Filestore,
    location: Location,
    se050: &mut Se05X<Twi, D>,
) -> Result<(), Error> {
    debug!("Deleting all pins");
    while let Some((entry, _)) = fs
        .read_dir_first(path!(""), location, &NotBefore::None)
        .map_err(|_| Error::ReadFailed)?
    {
        debug!("Deleting {}", entry.path());
        delete_from_path(entry.path(), fs, location, se050)?;
    }

    Ok(())
}
