use serde::{Deserialize, Serialize};
use trussed::{
    serde_extensions::{Extension, ExtensionClient, ExtensionResult},
    types::Bytes,
    Error,
};

#[derive(Debug, Default)]
pub struct ManageExtension;

/// Request information regarding the SE050
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct InfoRequest;

/// Test SE050 functionality
///
/// This is now a placeholder for the previous test. It is kept to return available space on the SE050
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct TestSe050Request;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
pub enum ManageRequest {
    Info(InfoRequest),
    TestSe050(TestSe050Request),
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
    Info(InfoReply),
    TestSe050(TestSe050Reply),
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

pub type ManageResult<'a, R, C> = ExtensionResult<'a, ManageExtension, R, C>;

pub trait ManageClient: ExtensionClient<ManageExtension> {
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
