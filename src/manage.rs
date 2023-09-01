use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use littlefs2::{path, path::Path};
use se05x::{
    se05x::{
        commands::{CreateSession, DeleteAll, VerifySessionUserId, WriteUserId},
        ObjectId,
    },
    t1::I2CForT1,
};
use serde::{Deserialize, Serialize};
use trussed::{
    serde_extensions::{Extension, ExtensionClient, ExtensionImpl, ExtensionResult},
    service::ServiceResources,
    store::Store,
    types::CoreContext,
    Error,
};

use crate::Se050Backend;

#[derive(Debug, Default)]
pub struct ManageExtension;

/// Factory reset the entire device
///
/// This will reset all filesystems as well as the SE050 secure element.
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct FactoryResetRequest;

#[derive(Debug, Deserialize, Serialize)]
pub enum ManageRequest {
    FactoryReset(FactoryResetRequest),
}

impl TryFrom<ManageRequest> for FactoryResetRequest {
    type Error = Error;
    fn try_from(request: ManageRequest) -> Result<Self, Self::Error> {
        match request {
            ManageRequest::FactoryReset(request) => Ok(request),
            // _ => Err(Error::InternalError),
        }
    }
}

impl From<FactoryResetRequest> for ManageRequest {
    fn from(request: FactoryResetRequest) -> Self {
        Self::FactoryReset(request)
    }
}

#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct FactoryResetReply;

#[derive(Debug, Deserialize, Serialize)]
pub enum ManageReply {
    FactoryReset(FactoryResetReply),
}

impl TryFrom<ManageReply> for FactoryResetReply {
    type Error = Error;
    fn try_from(request: ManageReply) -> Result<Self, Self::Error> {
        match request {
            ManageReply::FactoryReset(request) => Ok(request),
            // _ => Err(Error::InternalError),
        }
    }
}

impl From<FactoryResetReply> for ManageReply {
    fn from(request: FactoryResetReply) -> Self {
        Self::FactoryReset(request)
    }
}

impl Extension for ManageExtension {
    type Request = ManageRequest;
    type Reply = ManageReply;
}

impl<Twi: I2CForT1, D: DelayUs<u32>> ExtensionImpl<ManageExtension> for Se050Backend<Twi, D> {
    fn extension_request<P: trussed::Platform>(
        &mut self,
        _core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &<ManageExtension as Extension>::Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<<ManageExtension as Extension>::Reply, Error> {
        self.enable().map_err(|err| {
            debug_now!("Failed to enable for management: {err:?}");
            err
        })?;
        match request {
            ManageRequest::FactoryReset(_) => {
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
                        debug_now!("Failed to write factory reset user id: {_err:?}");
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
                        debug_now!("Failed to create reset session: {_err:?}");
                        Error::FunctionFailed
                    })?;

                self.se
                    .run_session_command(
                        session.session_id,
                        &VerifySessionUserId { user_id: data },
                        &mut buf,
                    )
                    .map_err(|_err| {
                        debug_now!("Failed to verify reset session: {_err:?}");
                        Error::FunctionFailed
                    })?;

                self.se
                    .run_session_command(session.session_id, &DeleteAll {}, &mut buf)
                    .map_err(|_err| {
                        debug_now!("Failed to factory reset: {_err:?}");
                        Error::FunctionFailed
                    })?;

                let platform = resources.platform();
                let store = platform.store();
                let ifs = &*store.ifs();
                let efs = &*store.efs();
                let vfs = &*store.vfs();
                ifs.remove_dir_all(path!("/")).map_err(|_err| {
                    debug_now!("Failed to delete ifs: {_err:?}");
                    Error::FunctionFailed
                })?;
                efs.remove_dir_all(path!("/")).map_err(|_err| {
                    debug_now!("Failed to delete efs: {_err:?}");
                    Error::FunctionFailed
                })?;
                vfs.remove_dir_all(path!("/")).map_err(|_err| {
                    debug_now!("Failed to delete vfs: {_err:?}");
                    Error::FunctionFailed
                })?;
                Ok(FactoryResetReply.into())
            }
        }
    }
}

type ManageResult<'a, R, C> = ExtensionResult<'a, ManageExtension, R, C>;

pub trait ManageClient: ExtensionClient<ManageExtension> {
    /// Factory reset the entire device
    ///
    /// This will reset all filesystems as well as the SE050 secure element.
    fn factory_reset(&mut self) -> ManageResult<'_, FactoryResetReply, Self> {
        self.extension(FactoryResetRequest)
    }
}

impl<C: ExtensionClient<ManageExtension>> ManageClient for C {}
