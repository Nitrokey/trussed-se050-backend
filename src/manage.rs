use embedded_hal::blocking::delay::DelayUs;
use se05x::t1::I2CForT1;
use serde::{Deserialize, Serialize};
use trussed::{
    serde_extensions::{Extension, ExtensionClient, ExtensionImpl, ExtensionResult},
    service::ServiceResources,
    types::{Bytes, CoreContext},
    Error,
};

mod se050_tests;

use crate::Se050Backend;

#[derive(Debug, Default)]
pub struct ManageExtension;

/// Test the  SE050
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct TestSe050Request;

#[derive(Debug, Deserialize, Serialize)]
pub enum ManageRequest {
    TestSe050(TestSe050Request),
}

impl TryFrom<ManageRequest> for TestSe050Request {
    type Error = Error;
    fn try_from(request: ManageRequest) -> Result<Self, Self::Error> {
        match request {
            ManageRequest::TestSe050(request) => Ok(request),
            // _ => Err(Error::InternalError),
        }
    }
}

impl From<TestSe050Request> for ManageRequest {
    fn from(request: TestSe050Request) -> Self {
        Self::TestSe050(request)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TestSe050Reply {
    pub reply: Bytes<1024>,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ManageReply {
    TestSe050(TestSe050Reply),
}

impl TryFrom<ManageReply> for TestSe050Reply {
    type Error = Error;
    fn try_from(request: ManageReply) -> Result<Self, Self::Error> {
        match request {
            ManageReply::TestSe050(request) => Ok(request),
            // _ => Err(Error::InternalError),
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
        _resources: &mut ServiceResources<P>,
    ) -> Result<<ManageExtension as Extension>::Reply, Error> {
        self.enable().map_err(|err| {
            debug_now!("Failed to enable for management: {err:?}");
            err
        })?;
        match request {
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
    /// Test the se050 device and driver
    ///
    /// This will factory reset the SE050, and test that most commands work as expected,
    /// ensuring that the device is functioning properly and that the driver is stable.
    fn test_se050(&mut self) -> ManageResult<'_, TestSe050Reply, Self> {
        self.extension(TestSe050Request)
    }
}
