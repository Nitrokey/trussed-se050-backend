use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use littlefs2::{path, path::Path};
use se05x::{
    se05x::{
        commands::{CreateSession, DeleteAll, VerifySessionUserId, WriteUserId},
        ObjectId, ProcessSessionCmd,
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
                    .or(Err(Error::FunctionFailed))?;
                let session = self
                    .se
                    .run_command(
                        &CreateSession {
                            object_id: ObjectId::FACTORY_RESET,
                        },
                        &mut buf,
                    )
                    .or(Err(Error::FunctionFailed))?;

                self.se
                    .run_command(
                        &ProcessSessionCmd {
                            session_id: session.session_id,
                            apdu: VerifySessionUserId { user_id: data },
                        },
                        &mut buf,
                    )
                    .or(Err(Error::FunctionFailed))?;

                self.se
                    .run_command(
                        &ProcessSessionCmd {
                            session_id: session.session_id,
                            apdu: DeleteAll {},
                        },
                        &mut buf,
                    )
                    .or(Err(Error::FunctionFailed))?;

                let platform = resources.platform();
                let store = platform.store();
                let ifs = &*store.ifs();
                let efs = &*store.efs();
                let vfs = &*store.vfs();
                ifs.remove_dir_all(path!(""))
                    .or(Err(Error::FunctionFailed))?;
                efs.remove_dir_all(path!(""))
                    .or(Err(Error::FunctionFailed))?;
                vfs.remove_dir_all(path!(""))
                    .or(Err(Error::FunctionFailed))?;
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
