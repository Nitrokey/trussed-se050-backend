use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;

use littlefs2::path::PathBuf;
use se05x::se05x::commands::{
    CreateSession, DeleteAll, VerifySessionUserId, WriteEcKey, WriteUserId,
};
use se05x::se05x::policies::{ObjectAccessRule, ObjectPolicyFlags, Policy, PolicySet};
use se05x::se05x::{EcCurve, ObjectId, P1KeyType};
use se05x::t1::I2CForT1;
use trussed::service::Keystore;
use trussed::types::Location;
use trussed::{
    api::{reply::UnwrapKey, request},
    serde_extensions::ExtensionImpl,
    service::{Filestore, ServiceResources},
    types::Bytes,
    types::{CoreContext, StorageAttributes},
    Error,
};
use trussed_hpke::HpkeExtension;
use trussed_manage::{ManageExtension, ManageRequest};
use trussed_wrap_key_to_file::{
    reply as ext_reply, WrapKeyToFileExtension, WrapKeyToFileReply, WrapKeyToFileRequest,
};

use crate::namespacing::{NamespaceValue, VolatileObjectId};
use crate::{core_api::CORE_DIR, Se050Backend, BACKEND_DIR};

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
                self.configured = false;

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
        se050_keystore: &mut impl Keystore,
        ns: NamespaceValue,
    ) -> Result<(hpke::SharedSecret, hpke::PublicKey), Error> {
        let object_id = VolatileObjectId::new(se050_keystore.rng(), ns);
        let buf = &mut [0; 100];
        self.se
            .run_command(
                WriteEcKey::builder()
                    .transient(true)
                    .key_type(P1KeyType::KeyPair)
                    .policy(POLICY)
                    .object_id(*object_id)
                    .curve(EcCurve::IdEccMontDh25519)
                    .build(),
                buf,
            )
            .map_err(|_err| {
                // error!("Failed to generate volatile key: {_err:?}");
                error!("Failed to generate volatile key: {_err:?}",);
                Error::FunctionFailed
            })?;

        todo!()
    }
    fn hpke_decap(&mut self, se050_keystore: &mut impl Keystore, ns: NamespaceValue) {
        todo!()
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
        todo!()
    }
}
