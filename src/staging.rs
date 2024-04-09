use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;

use littlefs2::path::PathBuf;
use se05x::se05x::commands::{
    CreateSession, DeleteAll, DeleteSecureObject, EcdhGenerateSharedSecret, ReadObject,
    VerifySessionUserId, WriteEcKey, WriteUserId,
};
use se05x::se05x::policies::{ObjectAccessRule, ObjectPolicyFlags, Policy, PolicySet};
use se05x::se05x::{EcCurve, ObjectId, P1KeyType};
use se05x::t1::I2CForT1;
use serde::{Deserialize, Serialize};
use trussed::config::MAX_SERIALIZED_KEY_LENGTH;
use trussed::key::{self};
use trussed::service::Keystore;
use trussed::types::{KeyId, Location};
use trussed::{
    api::{reply::UnwrapKey, request},
    serde_extensions::ExtensionImpl,
    service::{Filestore, ServiceResources},
    types::Bytes,
    types::{CoreContext, StorageAttributes},
    Error,
};
use trussed_hpke::{
    HpkeExtension, HpkeOpenKeyFromFileReply, HpkeOpenKeyReply, HpkeOpenReply, HpkeRequest,
    HpkeSealKeyReply, HpkeSealKeyToFileReply, HpkeSealReply,
};
use trussed_manage::{ManageExtension, ManageRequest};
use trussed_wrap_key_to_file::{
    reply as ext_reply, WrapKeyToFileExtension, WrapKeyToFileReply, WrapKeyToFileRequest,
};

use crate::{
    core_api::{ItemsToDelete, WrappedKeyType, CORE_DIR},
    namespacing::{
        parse_key_id, KeyType, NamespaceValue, ParsedObjectId, PersistentObjectId, VolatileObjectId,
    },
    Se050Backend, BACKEND_DIR,
};

use self::hpke::{extract_and_expand, TAG_LEN};

mod hpke;

impl<Twi: I2CForT1, D: DelayUs<u32>> ExtensionImpl<WrapKeyToFileExtension>
    for Se050Backend<Twi, D>
{
    fn extension_request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        backend_ctx: &mut Self::Context,
        request: &WrapKeyToFileRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<WrapKeyToFileReply, Error> {
        self.configure()?;

        // FIXME: Have a real implementation from trussed
        let mut backend_path = core_ctx.path.clone();
        backend_path.push(&PathBuf::from(BACKEND_DIR));
        backend_path.push(&PathBuf::from(CORE_DIR));

        let core_keystore = &mut resources.keystore(core_ctx.path.clone())?;
        let se050_keystore = &mut resources.keystore(backend_path)?;
        let filestore = &mut resources.filestore(core_ctx.path.clone());
        let backend_ctx = backend_ctx.with_namespace(&self.ns, &core_ctx.path);
        let ns = backend_ctx.ns;
        match request {
            WrapKeyToFileRequest::WrapKeyToFile(req) => {
                debug!("Wrapping key to file: {:?}", req.key);
                let res = self.wrap_key(
                    &request::WrapKey {
                        mechanism: req.mechanism,
                        wrapping_key: req.wrapping_key,
                        key: req.key,
                        associated_data: Bytes::from_slice(&req.associated_data)
                            .map_err(|_| Error::FunctionFailed)?,
                        // TODO: add nonce support?
                        nonce: None,
                    },
                    core_keystore,
                    se050_keystore,
                    ns,
                )?;
                filestore.write(&req.path, req.location, &res.wrapped_key)?;
                Ok(ext_reply::WrapKeyToFile::default().into())
            }
            WrapKeyToFileRequest::UnwrapKeyFromFile(req) => {
                debug!("UnWrapping key from file");
                let data = filestore.read(&req.path, req.file_location)?;
                let UnwrapKey { key } = self.unwrap_key(
                    &request::UnwrapKey {
                        mechanism: req.mechanism,
                        wrapping_key: req.key,
                        wrapped_key: data,
                        associated_data: req.associated_data.clone(),
                        // TODO: add nonce support?
                        nonce: Default::default(),
                        attributes: StorageAttributes::new().set_persistence(req.key_location),
                    },
                    core_keystore,
                    se050_keystore,
                    ns,
                )?;
                Ok(ext_reply::UnwrapKeyFromFile { key }.into())
            }
        }
    }
}

impl<Twi: I2CForT1, D: DelayUs<u32>> ExtensionImpl<ManageExtension> for Se050Backend<Twi, D> {
    fn extension_request<P: trussed::Platform>(
        &mut self,
        _core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &ManageRequest,
        _resources: &mut ServiceResources<P>,
    ) -> Result<<ManageExtension as trussed::serde_extensions::Extension>::Reply, Error> {
        match request {
            ManageRequest::FactoryResetDevice(trussed_manage::FactoryResetDeviceRequest) => {
                let mut buf = [b'a'; 128];
                let data = &hex!("31323334");

                self.se
                    .run_command(
                        &WriteUserId {
                            policy: None,
                            max_attempts: None,
                            object_id: ObjectId::FACTORY_RESET,
                            data,
                        },
                        &mut buf,
                    )
                    .map_err(|_err| {
                        debug!("Failed to write factory reset user id: {_err:?}");
                        Error::FunctionFailed
                    })?;
                let session = self
                    .se
                    .run_command(
                        &CreateSession {
                            object_id: ObjectId::FACTORY_RESET,
                        },
                        &mut buf,
                    )
                    .map_err(|_err| {
                        debug!("Failed to create reset session: {_err:?}");
                        Error::FunctionFailed
                    })?;

                self.se
                    .run_session_command(
                        session.session_id,
                        &VerifySessionUserId { user_id: data },
                        &mut buf,
                    )
                    .map_err(|_err| {
                        debug!("Failed to verify reset session: {_err:?}");
                        Error::FunctionFailed
                    })?;

                self.se
                    .run_session_command(session.session_id, &DeleteAll {}, &mut buf)
                    .map_err(|_err| {
                        debug!("Failed to factory reset: {_err:?}");
                        Error::FunctionFailed
                    })?;
                self.configure()?;

                // Let the staging backend delete the rest of the data
                Err(Error::RequestNotAvailable)
            }
            ManageRequest::FactoryResetClient(trussed_manage::FactoryResetClientRequest {
                client,
            }) => {
                let ns = self.ns.for_client(client).ok_or_else(|| {
                    debug_now!("Attempt to factory reset client not handled by the SE050 backend");
                    Error::RequestNotAvailable
                })?;
                self.delete_all_items(
                    ItemsToDelete::KEYS | ItemsToDelete::PINS,
                    &[Location::Volatile, Location::External, Location::Internal],
                    ns,
                )?;
                // Let the staging backend delete the rest of the data
                Err(Error::RequestNotAvailable)
            }
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

impl<Twi: I2CForT1, D: DelayUs<u32>> Se050Backend<Twi, D> {
    fn hpke_encap(
        &mut self,
        pkr: KeyId,
        core_keystore: &mut impl Keystore,
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<(hpke::SharedSecret, hpke::PublicKey), Error> {
        let pkr = core_keystore.load_key(key::Secrecy::Public, Some(key::Kind::X255), &pkr)?;

        let enc_object_id = VolatileObjectId::new(se050_keystore.rng(), ns);
        let buf = &mut [0; 128];
        self.se
            .run_command(
                &WriteEcKey::builder()
                    .transient(true)
                    .key_type(P1KeyType::KeyPair)
                    .policy(POLICY)
                    .object_id(*enc_object_id)
                    .curve(EcCurve::IdEccMontDh25519)
                    .build(),
                buf,
            )
            .map_err(|_err| {
                error!("Failed to generate volatile key: {_err:?}",);
                Error::FunctionFailed
            })?;
        let enc = self
            .se
            .run_command(
                &ReadObject::builder().object_id(*enc_object_id).build(),
                buf,
            )
            .map_err(|_err| {
                error!("Failed to read generated key: {_err:?}",);
                Error::FunctionFailed
            })?;
        let enc: hpke::PublicKey = enc.data.try_into()?;
        let dh = self
            .se
            .run_command(
                &EcdhGenerateSharedSecret::builder()
                    .key_id(*enc_object_id)
                    .public_key(&pkr.material)
                    .build(),
                buf,
            )
            .map_err(|_err| {
                error!("Failed to generate shared secret: {_err:?}",);
                Error::FunctionFailed
            })?;

        let dh: hpke::SharedSecret = dh.shared_secret.try_into()?;

        let kem_context = &mut [0; 64];
        kem_context[0..32].copy_from_slice(&*enc);
        kem_context[32..].copy_from_slice(&pkr.material);
        let shared_secret = hpke::extract_and_expand(dh, kem_context).into();
        self.se
            .run_command(
                &DeleteSecureObject {
                    object_id: *enc_object_id,
                },
                buf,
            )
            .map_err(|_err| {
                error!("Failed to read generated key: {_err:?}",);
                Error::FunctionFailed
            })?;
        Ok((shared_secret, enc))
    }

    fn hpke_setup_base_s(
        &mut self,
        pkr: KeyId,
        info: &[u8],
        core_keystore: &mut impl Keystore,
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<(hpke::PublicKey, hpke::Context), Error> {
        let (shared_secret, enc) = self.hpke_encap(pkr, core_keystore, se050_keystore, ns)?;
        let ctx = hpke::key_schedule(shared_secret, info);
        Ok((enc, ctx))
    }

    #[allow(clippy::too_many_arguments)]
    fn hpke_seal(
        &mut self,
        pkr: KeyId,
        info: &[u8],
        aad: &[u8],
        ciphertext: &mut [u8],
        core_keystore: &mut impl Keystore,
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<(hpke::PublicKey, [u8; hpke::TAG_LEN]), Error> {
        let (enc, ctx) = self.hpke_setup_base_s(pkr, info, core_keystore, se050_keystore, ns)?;
        let tag = ctx.seal_in_place_detached(aad, ciphertext);
        Ok((enc, tag))
    }

    fn hpke_decap(
        &mut self,
        private_key: KeyId,
        enc: hpke::PublicKey,
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<hpke::SharedSecret, Error> {
        let (priv_parsed_key, priv_parsed_ty) =
            parse_key_id(private_key, ns).ok_or(Error::RequestNotAvailable)?;

        if !matches!(priv_parsed_ty, KeyType::X255) {
            return Err(Error::WrongKeyKind);
        }

        if let ParsedObjectId::VolatileKey(priv_volatile) = priv_parsed_key {
            self.reimport_volatile_key(
                private_key,
                key::Kind::X255,
                se050_keystore,
                priv_volatile.0,
            )?;
        }

        let (ParsedObjectId::VolatileKey(VolatileObjectId(priv_obj))
        | ParsedObjectId::PersistentKey(PersistentObjectId(priv_obj))) = priv_parsed_key
        else {
            return Err(Error::MechanismParamInvalid);
        };

        let buf = &mut [0; 128];

        let dh = self
            .se
            .run_command(
                &EcdhGenerateSharedSecret::builder()
                    .key_id(priv_obj)
                    .public_key(&*enc)
                    .build(),
                buf,
            )
            .map_err(|_err| {
                error!("Failed to generate shared secret: {_err:?}",);
                Error::FunctionFailed
            })?;

        let dh: hpke::SharedSecret = dh.shared_secret.try_into()?;

        let pkr = self
            .se
            .run_command(&ReadObject::builder().object_id(priv_obj).build(), buf)
            .map_err(|_err| {
                error!("Failed to read generated key: {_err:?}",);
                Error::FunctionFailed
            })?;
        let pkr: hpke::PublicKey = pkr.data.try_into()?;

        let kem_context = &mut [0; 64];
        kem_context[0..32].copy_from_slice(&*enc);
        kem_context[32..].copy_from_slice(&*pkr);
        let shared_secret = extract_and_expand(dh, kem_context).into();

        if let ParsedObjectId::VolatileKey(k) = priv_parsed_key {
            self.clear_volatile_key(k.0)?;
        }

        Ok(shared_secret)
    }

    fn hpke_setup_base_r(
        &mut self,
        pkr: KeyId,
        enc: hpke::PublicKey,
        info: &[u8],
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<hpke::Context, Error> {
        let shared_secret = self.hpke_decap(pkr, enc, se050_keystore, ns)?;
        let context = hpke::key_schedule(shared_secret, info);
        Ok(context)
    }

    #[allow(clippy::too_many_arguments)]
    fn hpke_open(
        &mut self,
        pkr: KeyId,
        enc: hpke::PublicKey,
        info: &[u8],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: [u8; hpke::TAG_LEN],
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<(), Error> {
        let ctx = self.hpke_setup_base_r(pkr, enc, info, se050_keystore, ns)?;
        ctx.open_in_place_detached(aad, ciphertext, tag)
            .map_err(|_| Error::AeadError)?;
        Ok(())
    }

    fn load_wrap_key_data(
        &mut self,
        key: KeyId,
        core_keystore: &mut impl Keystore,
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<UnsealedKey, Error> {
        if let Some((key, ty)) = self.wrap_key_data(key, se050_keystore, ns)? {
            return Ok(UnsealedKey {
                data: key.serialize().into(),
                kind: ty.into(),
            });
        }

        let key = core_keystore.load_key(key::Secrecy::Secret, None, &key)?;
        Ok(UnsealedKey {
            data: key.serialize().into(),
            kind: KeyKind::Core,
        })
    }

    fn store_wrap_key_data(
        &mut self,
        data: &UnsealedKey,
        location: Location,
        core_keystore: &mut impl Keystore,
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<KeyId, Error> {
        let key = key::Key::try_deserialize(&data.data)?;
        match data.kind {
            KeyKind::Core => {
                core_keystore.store_key(location, key::Secrecy::Secret, key.kind, &key.material)
            }
            KeyKind::Se050(ty) => self.store_unwrapped_key_data(ty, &data.data, se050_keystore, ns),
        }
    }
}

fn load_hpke_public_key(
    key_id: &KeyId,
    keystore: &mut impl Keystore,
) -> Result<hpke::PublicKey, trussed::Error> {
    let public_bytes: [u8; 32] = keystore
        .load_key(key::Secrecy::Public, Some(key::Kind::X255), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| trussed::Error::InternalError)?;
    Ok(public_bytes.into())
}

#[derive(Serialize, Deserialize, Clone, Copy)]
enum KeyKind {
    Core,
    Se050(WrappedKeyType),
}

impl From<WrappedKeyType> for KeyKind {
    fn from(value: WrappedKeyType) -> Self {
        Self::Se050(value)
    }
}

#[derive(Deserialize, Serialize)]
struct UnsealedKey {
    #[serde(rename = "d")]
    data: Bytes<MAX_SERIALIZED_KEY_LENGTH>,
    #[serde(rename = "k")]
    kind: KeyKind,
}

const TAG_OVERHEAD: usize = TAG_LEN;
const ENC_OVERHEAD: usize = 32;
const HPKE_OVERHEAD: usize = TAG_OVERHEAD + ENC_OVERHEAD;

impl UnsealedKey {
    // encoding: |map(2) | text(1) | "d" | bytes (len as u16) | MAX_SERIALIZED_KEY_LENGTH | data
    // | text(1) | "k" | array(1 if core, 2 if se050) | discriminator | (discriminiator) if se050 |
    fn serialize(&self) -> Bytes<{ MAX_SERIALIZED_KEY_LENGTH + 11 + HPKE_OVERHEAD }> {
        cbor_smol::cbor_serialize_bytes(&self).unwrap()
    }
    fn try_deserialize(data: &[u8]) -> Result<Self, Error> {
        cbor_smol::cbor_deserialize(data).map_err(|_| Error::CborError)
    }
}

impl<Twi: I2CForT1, D: DelayUs<u32>> ExtensionImpl<HpkeExtension> for Se050Backend<Twi, D> {
    fn extension_request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        backend_ctx: &mut Self::Context,
        request: &<HpkeExtension as trussed::serde_extensions::Extension>::Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<<HpkeExtension as trussed::serde_extensions::Extension>::Reply, Error> {
        self.configure()?;

        // FIXME: Have a real implementation from trussed
        let mut backend_path = core_ctx.path.clone();
        backend_path.push(&PathBuf::from(BACKEND_DIR));
        backend_path.push(&PathBuf::from(CORE_DIR));
        let filestore = &mut resources.filestore(core_ctx.path.clone());

        let core_keystore = &mut resources.keystore(core_ctx.path.clone())?;
        let se050_keystore = &mut resources.keystore(backend_path.clone())?;

        let backend_ctx = backend_ctx.with_namespace(&self.ns, &core_ctx.path);
        let ns = backend_ctx.ns;

        match request {
            HpkeRequest::Seal(req) => {
                let mut pt = req.plaintext.clone();
                let (pk, tag) = self.hpke_seal(
                    req.key,
                    &req.info,
                    &req.aad,
                    &mut pt,
                    core_keystore,
                    se050_keystore,
                    ns,
                )?;
                let enc = core_keystore.store_key(
                    req.enc_location,
                    key::Secrecy::Public,
                    key::Kind::X255,
                    &*pk,
                )?;
                Ok(HpkeSealReply {
                    enc,
                    ciphertext: pt,
                    tag: tag.into(),
                }
                .into())
            }
            HpkeRequest::SealKey(req) => {
                let mut pt = self
                    .load_wrap_key_data(req.key_to_seal, core_keystore, se050_keystore, ns)?
                    .serialize();
                let (enc, tag) = self.hpke_seal(
                    req.public_key,
                    &req.info,
                    &req.aad,
                    &mut pt,
                    core_keystore,
                    se050_keystore,
                    ns,
                )?;
                pt.extend_from_slice(&*enc)
                    .map_err(|_| Error::ImplementationError)?;
                pt.extend_from_slice(&tag)
                    .map_err(|_| Error::ImplementationError)?;
                let data = Bytes::from_slice(&pt).map_err(|_| {
                    error_now!("Wrapped key is too large. Use WrappKeyToFile instead");
                    Error::InternalError
                })?;
                Ok(HpkeSealKeyReply { data }.into())
            }
            HpkeRequest::SealKeyToFile(req) => {
                let mut pt = self
                    .load_wrap_key_data(req.key_to_seal, core_keystore, se050_keystore, ns)?
                    .serialize();
                let (enc, tag) = self.hpke_seal(
                    req.public_key,
                    &req.info,
                    &req.aad,
                    &mut pt,
                    core_keystore,
                    se050_keystore,
                    ns,
                )?;
                pt.extend_from_slice(&*enc)
                    .map_err(|_| Error::ImplementationError)?;
                pt.extend_from_slice(&tag)
                    .map_err(|_| Error::ImplementationError)?;
                filestore.write(&req.file, req.location, &pt)?;
                Ok(HpkeSealKeyToFileReply {}.into())
            }
            HpkeRequest::Open(req) => {
                let mut ct = req.ciphertext.clone();
                let enc = load_hpke_public_key(&req.enc_key, core_keystore)?;
                self.hpke_open(
                    req.key,
                    enc,
                    &req.info,
                    &req.aad,
                    &mut ct,
                    req.tag.into(),
                    se050_keystore,
                    ns,
                )?;

                Ok(HpkeOpenReply { plaintext: ct }.into())
            }
            HpkeRequest::OpenKey(req) => {
                let mut ct = req.sealed_key.clone();
                let (ct, tag) = ct.split_last_chunk_mut().ok_or(trussed::Error::AeadError)?;
                let (ct, enc_bytes) = ct.split_last_chunk_mut().ok_or(trussed::Error::AeadError)?;

                let enc = (*enc_bytes).into();
                self.hpke_open(
                    req.key,
                    enc,
                    &req.info,
                    &req.aad,
                    ct,
                    *tag,
                    se050_keystore,
                    ns,
                )?;
                let unsealed_key = UnsealedKey::try_deserialize(ct)?;
                let key = self.store_wrap_key_data(
                    &unsealed_key,
                    req.location,
                    core_keystore,
                    se050_keystore,
                    ns,
                )?;

                Ok(HpkeOpenKeyReply { key }.into())
            }
            HpkeRequest::OpenKeyFromFile(req) => {
                let mut ct: Bytes<{ MAX_SERIALIZED_KEY_LENGTH + 32 + 16 }> =
                    filestore.read(&req.sealed_key, req.sealed_location)?;
                let (ct, tag) = ct.split_last_chunk_mut().ok_or(trussed::Error::AeadError)?;
                let (ct, enc_bytes) = ct.split_last_chunk_mut().ok_or(trussed::Error::AeadError)?;

                let enc = (*enc_bytes).into();
                self.hpke_open(
                    req.key,
                    enc,
                    &req.info,
                    &req.aad,
                    ct,
                    *tag,
                    se050_keystore,
                    ns,
                )?;
                let unsealed_key = UnsealedKey::try_deserialize(ct)?;
                let key = self.store_wrap_key_data(
                    &unsealed_key,
                    req.unsealed_location,
                    core_keystore,
                    se050_keystore,
                    ns,
                )?;

                Ok(HpkeOpenKeyFromFileReply { key }.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsealed_key_size() {
        let unsealed_key = UnsealedKey {
            data: Bytes::from_slice(&[0; MAX_SERIALIZED_KEY_LENGTH]).unwrap(),
            kind: KeyKind::Core,
        };

        unsealed_key.serialize();

        let unsealed_key = UnsealedKey {
            data: Bytes::from_slice(&[0; MAX_SERIALIZED_KEY_LENGTH]).unwrap(),
            kind: KeyKind::Se050(WrappedKeyType::Volatile),
        };

        unsealed_key.serialize();

        let unsealed_key = UnsealedKey {
            data: Bytes::from_slice(&[0; MAX_SERIALIZED_KEY_LENGTH]).unwrap(),
            kind: KeyKind::Se050(WrappedKeyType::VolatileRsa),
        };

        let data = unsealed_key.serialize();
        assert_eq!(data.len() + HPKE_OVERHEAD, data.capacity());
    }
}
