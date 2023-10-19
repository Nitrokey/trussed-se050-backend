use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use littlefs2::{path, path::Path};
use se05x::{
    se05x::{
        commands::{
            CreateSession, DeleteAll, GetFreeMemory, GetVersion, ReadIdList, VerifySessionUserId,
            WriteUserId,
        },
        ObjectId, SecureObjectFilter,
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

/// Request information regarding the SE050
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct InfoRequest;

#[derive(Debug, Deserialize, Serialize)]
pub enum ManageRequest {
    FactoryReset(FactoryResetRequest),
    Info(InfoRequest),
}

impl TryFrom<ManageRequest> for FactoryResetRequest {
    type Error = Error;
    fn try_from(request: ManageRequest) -> Result<Self, Self::Error> {
        match request {
            ManageRequest::FactoryReset(request) => Ok(request),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<FactoryResetRequest> for ManageRequest {
    fn from(request: FactoryResetRequest) -> Self {
        Self::FactoryReset(request)
    }
}

impl TryFrom<ManageRequest> for InfoRequest {
    type Error = Error;
    fn try_from(request: ManageRequest) -> Result<Self, Self::Error> {
        match request {
            ManageRequest::Info(request) => Ok(request),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<InfoRequest> for ManageRequest {
    fn from(request: InfoRequest) -> Self {
        Self::Info(request)
    }
}

#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct FactoryResetReply;

#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct InfoReply {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
    pub sb_major: u8,
    pub sb_minor: u8,
    pub persistent: u16,
    pub transient_deselect: u16,
    pub transient_reset: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ManageReply {
    FactoryReset(FactoryResetReply),
    Info(InfoReply),
}

impl TryFrom<ManageReply> for FactoryResetReply {
    type Error = Error;
    fn try_from(request: ManageReply) -> Result<Self, Self::Error> {
        match request {
            ManageReply::FactoryReset(request) => Ok(request),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<FactoryResetReply> for ManageReply {
    fn from(request: FactoryResetReply) -> Self {
        Self::FactoryReset(request)
    }
}

impl TryFrom<ManageReply> for InfoReply {
    type Error = Error;
    fn try_from(request: ManageReply) -> Result<Self, Self::Error> {
        match request {
            ManageReply::Info(request) => Ok(request),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<InfoReply> for ManageReply {
    fn from(request: InfoReply) -> Self {
        Self::Info(request)
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
        self.configure().map_err(|err| {
            debug_now!("Failed to enable for management: {err:?}");
            err
        })?;

        debug_now!("Runnig manage request: {request:?}");
        match request {
            ManageRequest::FactoryReset(FactoryResetRequest) => {
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
                let id_list = self
                    .se
                    .run_command(
                        &ReadIdList::builder()
                            .offset(0.into())
                            .filter(SecureObjectFilter::All)
                            .build(),
                        &mut buf,
                    )
                    .map_err(|_err| {
                        debug_now!("Failed to factory reset: {_err:?}");
                        Error::FunctionFailed
                    })?;
                for obj in id_list.ids.chunks(4) {
                    debug_now!("Id: {}", hex_str!(obj, 4));
                }
                debug_now!("More: {:?}", id_list.more);

                const PATHS_TO_SAVE: &[&Path] = &[path!("fido/x5c/00"), path!("fido/sec/00")];

                let platform = resources.platform();
                let store = platform.store();
                let ifs = store.ifs();
                let efs = store.efs();
                let vfs = store.vfs();
                ifs.remove_dir_all_where(path!("/"), &|f| {
                    let file_name = f.file_name();
                    if PATHS_TO_SAVE.contains(&file_name) {
                        return false;
                    }
                    true
                })
                .map_err(|_err| {
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

                self.configured = false;

                Ok(FactoryResetReply.into())
            }
            ManageRequest::Info(InfoRequest) => {
                use se05x::se05x::Memory;
                let buf = &mut [0; 128];
                let atr = self
                    .se
                    .run_command(&GetVersion {}, buf)
                    .map_err(|_err| {
                        error_now!("Failed to get atr: {_err:?}");
                        Error::FunctionFailed
                    })?
                    .version_info;
                let free_persistent = self
                    .se
                    .run_command(
                        &GetFreeMemory {
                            memory: Memory::Persistent,
                        },
                        buf,
                    )
                    .map_err(|_err| {
                        error_now!("Failed to persistent mem: {_err:?}");
                        Error::FunctionFailed
                    })?
                    .available;
                let free_transient_deselect = self
                    .se
                    .run_command(
                        &GetFreeMemory {
                            memory: Memory::TransientDeselect,
                        },
                        buf,
                    )
                    .map_err(|_err| {
                        error_now!("Failed to TransientDeselect mem: {_err:?}");
                        Error::FunctionFailed
                    })?
                    .available;
                let free_transient_reset = self
                    .se
                    .run_command(
                        &GetFreeMemory {
                            memory: Memory::TransientReset,
                        },
                        buf,
                    )
                    .map_err(|_err| {
                        error_now!("Failed to TransientReset mem: {_err:?}");
                        Error::FunctionFailed
                    })?
                    .available;

                Ok(InfoReply {
                    major: atr.major,
                    minor: atr.minor,
                    patch: atr.patch,
                    sb_major: atr.secure_box_major,
                    sb_minor: atr.secure_box_minor,
                    persistent: free_persistent.0,
                    transient_deselect: free_transient_deselect.0,
                    transient_reset: free_transient_reset.0,
                }
                .into())
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

    /// Get info on the SE050
    fn get_info(&mut self) -> ManageResult<'_, InfoReply, Self> {
        self.extension(InfoRequest)
    }
}

impl<C: ExtensionClient<ManageExtension>> ManageClient for C {}
