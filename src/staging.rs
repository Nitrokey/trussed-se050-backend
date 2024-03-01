use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;

use littlefs2::path::PathBuf;
use se05x::se05x::commands::{CreateSession, DeleteAll, VerifySessionUserId, WriteUserId};
use se05x::se05x::ObjectId;
use se05x::t1::I2CForT1;
use trussed::types::Location;
use trussed::{
    api::{reply::UnwrapKey, request},
    serde_extensions::ExtensionImpl,
    service::{Filestore, ServiceResources},
    types::Bytes,
    types::{CoreContext, StorageAttributes},
    Error,
};
use trussed_staging::manage::{self, ManageExtension, ManageRequest};
use trussed_staging::wrap_key_to_file::{
    reply as ext_reply, WrapKeyToFileExtension, WrapKeyToFileReply, WrapKeyToFileRequest,
};

use crate::{core_api::CORE_DIR, Se050Backend, BACKEND_DIR};

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
            ManageRequest::FactoryResetDevice(manage::FactoryResetDeviceRequest) => {
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
            ManageRequest::FactoryResetClient(manage::FactoryResetClientRequest { client }) => {
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
