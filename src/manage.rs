use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use littlefs2::{path, path::Path};
use se05x::{
    se05x::{
        commands::{
            CreateSession, DeleteAll, GetFreeMemory, GetVersion, ReadIdList, VerifySessionUserId,
            WriteUserId,
        },
        Memory, ObjectId, SecureObjectFilter,
    },
    t1::I2CForT1,
};
use serde::{Deserialize, Serialize};
use trussed::{
    serde_extensions::{Extension, ExtensionClient, ExtensionImpl, ExtensionResult},
    service::ServiceResources,
    store::Store,
    types::Bytes,
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

/// Test SE050 functionality
///
/// This is now a placeholder for the previous test. It is kept to return available space on the SE050
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct TestSe050Request;

#[derive(Debug, Deserialize, Serialize)]
pub enum ManageRequest {
    FactoryReset(FactoryResetRequest),
    Info(InfoRequest),
    TestSe050(TestSe050Request),
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

impl TryFrom<ManageRequest> for TestSe050Request {
    type Error = Error;
    fn try_from(request: ManageRequest) -> Result<Self, Self::Error> {
        match request {
            ManageRequest::TestSe050(request) => Ok(request),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<TestSe050Request> for ManageRequest {
    fn from(request: TestSe050Request) -> Self {
        Self::TestSe050(request)
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
    TestSe050(TestSe050Reply),
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TestSe050Reply {
    pub reply: Bytes<1024>,
}

impl TryFrom<ManageReply> for TestSe050Reply {
    type Error = Error;
    fn try_from(request: ManageReply) -> Result<Self, Self::Error> {
        match request {
            ManageReply::TestSe050(request) => Ok(request),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<TestSe050Reply> for ManageReply {
    fn from(request: TestSe050Reply) -> Self {
        Self::TestSe050(request)
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
            debug!("Failed to enable for management: {err:?}");
            err
        })?;

        debug!("Runnig manage request: {request:?}");
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
                        debug!("Failed to factory reset: {_err:?}");
                        Error::FunctionFailed
                    })?;
                for obj in id_list.ids.chunks(4) {
                    debug!("Id: {}", hex_str!(obj, 4));
                }
                debug!("More: {:?}", id_list.more);

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
                    debug!("Failed to delete ifs: {_err:?}");
                    Error::FunctionFailed
                })?;
                efs.remove_dir_all(path!("/")).map_err(|_err| {
                    debug!("Failed to delete efs: {_err:?}");
                    Error::FunctionFailed
                })?;
                vfs.remove_dir_all(path!("/")).map_err(|_err| {
                    debug!("Failed to delete vfs: {_err:?}");
                    Error::FunctionFailed
                })?;

                self.configured = false;

                Ok(FactoryResetReply.into())
            }
            ManageRequest::Info(InfoRequest) => {
                let buf = &mut [0; 128];
                let atr = self
                    .se
                    .run_command(&GetVersion {}, buf)
                    .map_err(|_err| {
                        error!("Failed to get atr: {_err:?}");
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
                        error!("Failed to persistent mem: {_err:?}");
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
                        error!("Failed to TransientDeselect mem: {_err:?}");
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
                        error!("Failed to TransientReset mem: {_err:?}");
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
            ManageRequest::TestSe050(_) => {
                let mut buf = [b'a'; 128];
                let mut reply = Bytes::new();
                let atr = self.enable()?;
                let map_err = |_err| {
                    debug!("Failed to get memory: {_err:?}");
                    trussed::Error::FunctionFailed
                };
                reply
                    .extend_from_slice(&[
                        atr.major,
                        atr.minor,
                        atr.patch,
                        atr.secure_box_major,
                        atr.secure_box_minor,
                    ])
                    .ok();

                let mem = self
                    .se
                    .run_command(
                        &GetFreeMemory {
                            memory: Memory::Persistent,
                        },
                        &mut buf,
                    )
                    .map_err(map_err)?;
                reply.extend_from_slice(&mem.available.0.to_be_bytes()).ok();
                let mem = self
                    .se
                    .run_command(
                        &GetFreeMemory {
                            memory: Memory::TransientReset,
                        },
                        &mut buf,
                    )
                    .map_err(map_err)?;
                reply.extend_from_slice(&mem.available.0.to_be_bytes()).ok();
                let mem = self
                    .se
                    .run_command(
                        &GetFreeMemory {
                            memory: Memory::TransientDeselect,
                        },
                        &mut buf,
                    )
                    .map_err(map_err)?;
                reply.extend_from_slice(&mem.available.0.to_be_bytes()).ok();
                for i in 1..113 {
                    reply.push(i).ok();
                }

                Ok(TestSe050Reply { reply }.into())
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

    /// Test the se050 device and driver
    ///
    /// This will fake the results of the tests from v0.1.0-test-driver for compatibility but
    /// return correct metadata header to be shown in the test result
    fn test_se050(&mut self) -> ManageResult<'_, TestSe050Reply, Self> {
        self.extension(TestSe050Request)
    }
}

impl<C: ExtensionClient<ManageExtension>> ManageClient for C {}
