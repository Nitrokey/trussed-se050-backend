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
    types::{Bytes, CoreContext},
    Error,
};

mod se050_tests;

use crate::Se050Backend;

#[derive(Debug, Default)]
pub struct ManageExtension;

/// Factory reset the entire device
///
/// This will reset all filesystems as well as the SE050 secure element.
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct FactoryResetRequest;

/// Test the  SE050
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct TestSe050Request;

#[derive(Debug, Deserialize, Serialize)]
pub enum ManageRequest {
    FactoryReset(FactoryResetRequest),
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TestSe050Reply {
    pub reply: Bytes<1024>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ManageReply {
    FactoryReset(FactoryResetReply),
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
            ManageRequest::TestSe050(TestSe050Request) => {
                let mut reply = Bytes::new();
                se050_tests::run_tests(&mut self.se, &mut reply)?;
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

    /// Test the se050 device and driver
    ///
    /// This will factory reset the SE050, and test that most commands work as expected,
    /// ensuring that the device is functioning properly and that the driver is stable.
    fn test_se050(&mut self) -> ManageResult<'_, TestSe050Reply, Self> {
        self.extension(TestSe050Request)
    }
}
