#![no_std]

use embedded_hal::blocking::delay::DelayUs;
use se05x::{
    se05x::{commands::GetRandom, Se05X},
    t1::I2CForT1,
};
use trussed::{
    api::{reply, request, Request},
    backend::Backend,
    config::MAX_MESSAGE_LENGTH,
    serde_extensions::ExtensionImpl,
    types::Message,
};

#[macro_use]
extern crate delog;
generate_macros!();

/// Need overhead for TLV + SW bytes
const BUFFER_LEN: usize = 2048;

pub struct Se050Backend<Twi, D> {
    se: Se05X<Twi, D>,
    enabled: bool,
    failed_enable: Option<se05x::se05x::Error>,
}

impl<Twi: I2CForT1, D: DelayUs<u32>> Se050Backend<Twi, D> {
    pub fn new(se: Se05X<Twi, D>) -> Self {
        Se050Backend {
            se,
            enabled: false,
            failed_enable: None,
        }
    }

    fn random_bytes(&mut self, count: usize) -> Result<trussed::Reply, trussed::Error> {
        if count >= MAX_MESSAGE_LENGTH {
            return Err(trussed::Error::MechanismParamInvalid);
        }

        if !self.enabled {
            if let Err(e) = self.se.enable() {
                self.failed_enable = Some(e);
            } else {
                self.failed_enable = None;
                self.enabled = true;
            }
        }
        if let Some(_e) = self.failed_enable {
            error!("Enabling failed: {:?}", _e);
            return Err(trussed::Error::FunctionFailed);
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
                trussed::Error::FunctionFailed
            })?;
        if res.data.len() != count {
            error!("Bad random length");
            return Err(trussed::Error::FunctionFailed);
        }
        Ok(reply::RandomBytes {
            bytes: Message::from_slice(res.data).unwrap(),
        }
        .into())
    }
}

impl<Twi: I2CForT1, D: DelayUs<u32>> Backend for Se050Backend<Twi, D> {
    type Context = ();

    fn request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut trussed::types::CoreContext,
        backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, trussed::Error> {
        match request {
            Request::RandomBytes(request::RandomBytes { count }) => self.random_bytes(*count),
            _ => Err(trussed::Error::RequestNotAvailable),
        }
    }
}
