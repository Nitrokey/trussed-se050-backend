//! Implementations of the core APIs for the SE050 backend

use embedded_hal::blocking::delay::DelayUs;
use se05x::t1::I2CForT1;
use trussed::{api::Request, backend::Backend, Error};

use crate::{Context, Se050Backend};
impl<Twi: I2CForT1, D: DelayUs<u32>> Backend for Se050Backend<Twi, D> {
    type Context = Context;

    fn request<P: trussed::Platform>(
        &mut self,
        _core_ctx: &mut trussed::types::CoreContext,
        _backend_ctx: &mut Self::Context,
        _request: &Request,
        _resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, Error> {
        Err(Error::RequestNotAvailable)
    }
}
