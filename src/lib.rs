#![cfg_attr(not(test), no_std)]

use embedded_hal::blocking::delay::DelayUs;
use se05x::{se05x::Se05X, t1::I2CForT1};

#[macro_use]
extern crate delog;
generate_macros!();

mod core_api;
pub mod manage;

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

    fn enable(&mut self) -> Result<(), trussed::Error> {
        if !self.enabled {
            debug!("Enabling");
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

        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct Context {}
