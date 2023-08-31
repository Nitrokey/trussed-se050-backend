#![cfg_attr(not(test), no_std)]

use core::ops::Range;

use embedded_hal::blocking::delay::DelayUs;
use littlefs2::path::Path;
use namespacing::{Namespace, NamespaceValue};
use se05x::{se05x::Se05X, t1::I2CForT1};
use trussed::{types::Location, Bytes};

#[macro_use]
extern crate delog;
generate_macros!();

mod trussed_auth_impl;
use trussed_auth::MAX_HW_KEY_LEN;
use trussed_auth_impl::{AuthContext, HardwareKey};

mod core_api;
mod namespacing;

/// Need overhead for TLV + SW bytes
const BACKEND_DIR: &str = "se050-bak";

pub enum Se05xLocation {
    Persistent,
    Transient,
}

impl From<Location> for Se05xLocation {
    fn from(value: Location) -> Self {
        match value {
            Location::Volatile => Self::Transient,
            Location::External | Location::Internal => Self::Persistent,
        }
    }
}

pub struct Se050Backend<Twi, D> {
    se: Se05X<Twi, D>,
    enabled: bool,
    failed_enable: Option<se05x::se05x::Error>,
    metadata_location: Location,
    hw_key: HardwareKey,
    ns: Namespace,
}

impl<Twi: I2CForT1, D: DelayUs<u32>> Se050Backend<Twi, D> {
    pub fn new(
        se: Se05X<Twi, D>,
        metadata_location: Location,
        hardware_key: Option<Bytes<{ MAX_HW_KEY_LEN }>>,
        ns: Namespace,
    ) -> Self {
        Se050Backend {
            se,
            enabled: false,
            failed_enable: None,
            metadata_location,
            hw_key: match hardware_key {
                None => HardwareKey::None,
                Some(k) => HardwareKey::Raw(k),
            },
            ns,
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
pub struct Context {
    auth: AuthContext,
    ns: Option<NamespaceValue>,
}

impl Context {
    fn with_namespace<'a>(&'a mut self, ns: &Namespace, client_id: &Path) -> ContextNs<'a> {
        let ns_val = self
            .ns
            .get_or_insert_with(|| ns.for_client(client_id).unwrap());
        ContextNs {
            ns: *ns_val,
            auth: &mut self.auth,
        }
    }
}

#[derive(Debug)]
pub struct ContextNs<'a> {
    auth: &'a mut AuthContext,
    ns: NamespaceValue,
}

const ID_RANGE: Range<u32> = 0x000000FF..0x7FFF0000;
