//! Implementations of the core APIs for the SE050 backend

use embedded_hal::blocking::delay::DelayUs;
use se05x::{se05x::commands::GetRandom, t1::I2CForT1};
use trussed::{
    api::{reply, request, Request},
    backend::Backend,
    config::MAX_MESSAGE_LENGTH,
    types::Message,
    Error,
};

use crate::{Context, Se050Backend};

const BUFFER_LEN: usize = 2048;

impl<Twi: I2CForT1, D: DelayUs<u32>> Se050Backend<Twi, D> {
    fn random_bytes(&mut self, count: usize) -> Result<trussed::Reply, Error> {
        if count >= MAX_MESSAGE_LENGTH {
            return Err(Error::MechanismParamInvalid);
        }

        let mut buf = [0; BUFFER_LEN];
        let res = self
            .se
            .run_command(
                &GetRandom {
                    length: (count as u16).into(),
                },
                &mut buf,
            )
            .map_err(|_err| {
                error!("Failed to get random: {:?}", _err);
                Error::FunctionFailed
            })?;
        if res.data.len() != count {
            error!("Bad random length");
            return Err(Error::FunctionFailed);
        }
        Ok(reply::RandomBytes {
            bytes: Message::from_slice(res.data).unwrap(),
        }
        .into())
    }
}

impl<Twi: I2CForT1, D: DelayUs<u32>> Backend for Se050Backend<Twi, D> {
    type Context = Context;

    fn request<P: trussed::Platform>(
        &mut self,
        _core_ctx: &mut trussed::types::CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &Request,
        _resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, Error> {
        self.enable()?;
        Ok(match request {
            Request::RandomBytes(request::RandomBytes { count }) => self.random_bytes(*count)?,
            _ => return Err(Error::RequestNotAvailable),
        })
    }
}
