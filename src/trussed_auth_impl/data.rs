use crate::{generate_object_id, trussed_auth_impl::KEY_LEN};

use super::{Error, Key, Salt, HASH_LEN, SALT_LEN};

use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use hmac::{Hmac, Mac};
use iso7816::Status;
use rand::Rng;
use se05x::{
    se05x::{
        commands::{CloseSession, CreateSession, GetRandom, ReadObject, WriteBinary, WriteSymmKey},
        policies::{ObjectAccessRule, ObjectPolicyFlags, Policy, PolicySet},
        Be, ObjectId, ProcessSessionCmd, Se05X, SessionId, SymmKeyType,
    },
    t1::I2CForT1,
};
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use sha2::Sha256;
use trussed::{
    platform::CryptoRng,
    service::{Filestore, RngCore},
    types::{Bytes, Location, PathBuf},
};
use trussed_auth::{PinId, MAX_PIN_LENGTH};

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
    pin_aes_key_id: ObjectId,
    /// Id of the binary object protected by the PIN. None if the PIN protects nothing
    protected_key_id: Option<ObjectId>,
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

fn key_policy(pin_aes_key_id: ObjectId, protected_key_id: ObjectId) -> [Policy; 2] {
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
    pub fn new<R: RngCore + CryptoRng>(id: PinId, rng: &mut R, derived_key: bool) -> Self {
        use rand::Rng;
        let salt = ByteArray::new(rng.gen());
        let pin_aes_key_id = generate_object_id(rng);
        let protected_key_id = derived_key.then(|| generate_object_id(rng));
        Self {
            id,
            salt,
            pin_aes_key_id,
            protected_key_id,
        }
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
        if let Some(protected_key_id) = self.protected_key_id {
            tmp1 = pin_policy_with_key(self.pin_aes_key_id, protected_key_id);
            pin_aes_key_policy = &tmp1;

            let protected_key_policy = &key_policy(self.pin_aes_key_id, protected_key_id);
            let key = se050.run_command(
                &GetRandom {
                    length: (KEY_LEN as u16).into(),
                },
                buf,
            )?;
            let key: Key = ByteArray::new(key.data.try_into().map_err(|_| Error::Se050)?);
            se050.run_command(
                &WriteBinary {
                    object_id: protected_key_id,
                    transient: false,
                    policy: Some(PolicySet(protected_key_policy)),
                    offset: Some(0.into()),
                    file_length: Some((KEY_LEN as u16).into()),
                    data: Some(&*key),
                },
                buf,
            )?;
        } else {
            tmp2 = simple_pin_policy(self.pin_aes_key_id);
            pin_aes_key_policy = &tmp2;
        }
        se050.run_command(
            &WriteSymmKey {
                transient: false,
                is_auth: true,
                key_type: SymmKeyType::Aes,
                policy: Some(PolicySet(pin_aes_key_policy)),
                max_attempts: retries.map(u16::from).map(Be::from),
                object_id: self.pin_aes_key_id,
                kek_id: None,
                value: &*pin_aes_key_value,
            },
            buf,
        )?;
        Ok(())
    }

    // Write the necessary objects to the SE050
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
    ) -> Result<Self, Error> {
        let this = Self::new(id, rng, true);
        this.save(fs, location)?;

        let buf = &mut [0; 128];
        let pin_aes_key_value = expand_pin_key(&this.salt, app_key, this.id, value);

        let protected_key_id = this.protected_key_id.unwrap();

        let pin_aes_key_policy = &pin_policy_with_key(this.pin_aes_key_id, protected_key_id);

        let protected_key_policy = &key_policy(this.pin_aes_key_id, protected_key_id);
        se050.run_command(
            &WriteBinary {
                object_id: protected_key_id,
                transient: false,
                policy: Some(PolicySet(protected_key_policy)),
                offset: Some(0.into()),
                file_length: Some((KEY_LEN as u16).into()),
                data: Some(&**key),
            },
            buf,
        )?;
        se050.run_command(
            &WriteSymmKey {
                transient: false,
                is_auth: true,
                key_type: SymmKeyType::Aes,
                policy: Some(PolicySet(pin_aes_key_policy)),
                max_attempts: retries.map(u16::from).map(Be::from),
                object_id: this.pin_aes_key_id,
                kek_id: None,
                value: &*pin_aes_key_value,
            },
            buf,
        )?;
        Ok(this)
    }

    pub fn check<Twi: I2CForT1, D: DelayUs<u32>, R: RngCore + CryptoRng>(
        &self,
        value: &[u8],
        app_key: &Key,
        se050: &mut Se05X<Twi, D>,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let buf = &mut [0; 1024];
        let pin_aes_key_value = expand_pin_key(&self.salt, app_key, self.id, value);
        let res = se050.run_command(
            &CreateSession {
                object_id: self.pin_aes_key_id,
            },
            buf,
        )?;
        let session_id = res.session_id;
        let res = match se050.authenticate_aes128_session(session_id, &pin_aes_key_value, rng) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        };
        se050.run_command(
            &ProcessSessionCmd {
                session_id,
                apdu: CloseSession {},
            },
            buf,
        )?;
        res
    }

    pub fn check_and_get_key<Twi: I2CForT1, D: DelayUs<u32>, R: RngCore + CryptoRng>(
        &self,
        value: &[u8],
        app_key: &Key,
        se050: &mut Se05X<Twi, D>,
        rng: &mut R,
    ) -> Result<Option<Key>, Error> {
        let Some(protected_key_id) = self.protected_key_id else {
            return Err(Error::BadPinType);
        };

        let buf = &mut [0; 1024];
        let pin_aes_key_value = expand_pin_key(&self.salt, app_key, self.id, value);
        let res = se050.run_command(
            &CreateSession {
                object_id: self.pin_aes_key_id,
            },
            buf,
        )?;
        let session_id = res.session_id;
        let res = match se050.authenticate_aes128_session(session_id, &pin_aes_key_value, rng) {
            Ok(()) => {
                let key = se050.run_command(
                    &ProcessSessionCmd {
                        session_id,
                        apdu: ReadObject {
                            object_id: protected_key_id,
                            offset: None,
                            length: Some((KEY_LEN as u16).into()),
                            rsa_key_component: None,
                        },
                    },
                    buf,
                )?;
                Ok(Some(
                    key.data
                        .try_into()
                        .map_err(|_| Error::DeserializationFailed)?,
                ))
            }
            Err(_) => Ok(None),
        };
        se050.run_command(
            &ProcessSessionCmd {
                session_id,
                apdu: CloseSession {},
            },
            buf,
        )?;
        res
    }

    pub fn update<Twi: I2CForT1, D: DelayUs<u32>, R: RngCore + CryptoRng>(
        &mut self,
        se050: &mut Se05X<Twi, D>,
        app_key: &Key,
        old_value: &[u8],
        new_value: &[u8],
        fs: &mut impl Filestore,
        location: Location,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let buf = &mut [0; 1024];
        let pin_aes_key_value = expand_pin_key(&self.salt, app_key, self.id, old_value);
        let res = se050.run_command(
            &CreateSession {
                object_id: self.pin_aes_key_id,
            },
            buf,
        )?;
        let session_id = res.session_id;
        let res = match se050.authenticate_aes128_session(session_id, &pin_aes_key_value, rng) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        };

        self.salt = ByteArray::new(rng.gen());
        let new_pin_aes_key_value = expand_pin_key(&self.salt, app_key, self.id, new_value);
        se050.run_command(
            &ProcessSessionCmd {
                session_id,
                apdu: WriteSymmKey {
                    transient: false,
                    is_auth: true,
                    key_type: SymmKeyType::Aes,
                    policy: None,
                    max_attempts: None,
                    object_id: self.pin_aes_key_id,
                    kek_id: None,
                    value: &*new_pin_aes_key_value,
                },
            },
            buf,
        )?;
        self.save(fs, location)?;
        se050.run_command(
            &ProcessSessionCmd {
                session_id,
                apdu: CloseSession {},
            },
            buf,
        )?;
        res
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
}
