#![cfg_attr(not(test), no_std)]

use core::ops::Range;

use embedded_hal::blocking::delay::DelayUs;
use hex_literal::hex;
use littlefs2::path;
use littlefs2::path::Path;
use namespacing::{Namespace, NamespaceValue};
use se05x::{
    se05x::{commands::ReadEcCurveList, Atr, EcCurve, ObjectId, Se05X},
    t1::I2CForT1,
};
use trussed::{types::Location, Bytes};

#[macro_use]
extern crate delog;
generate_macros!();

mod trussed_auth_impl;
use trussed_auth::MAX_HW_KEY_LEN;
use trussed_auth_impl::{AuthContext, HardwareKey};

mod staging;

mod core_api;
pub mod manage;
pub mod migrate;
pub mod namespacing;

/// Need overhead for TLV + SW bytes
const BACKEND_DIR: &Path = path!("se050-bak");

pub const GLOBAL_ATTEST_ID: ObjectId = ObjectId(hex!("F0000012"));

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

enum EnableState {
    NotEnabled,
    Enabled(Atr),
    Failed(se05x::se05x::Error),
}

pub struct Se050Backend<Twi, D> {
    se: Se05X<Twi, D>,
    enabled: EnableState,
    metadata_location: Location,
    hw_key: HardwareKey,
    ns: Namespace,
    configured: bool,
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
            enabled: EnableState::NotEnabled,
            metadata_location,
            hw_key: match hardware_key {
                None => HardwareKey::None,
                Some(k) => HardwareKey::Raw(k),
            },
            ns,
            configured: false,
        }
    }

    fn enable(&mut self) -> Result<Atr, trussed::Error> {
        match self.enabled {
            EnableState::NotEnabled => match self.se.enable() {
                Err(err) => {
                    error!("Enabling failed: {:?}", err);
                    self.enabled = EnableState::Failed(err);
                    Err(trussed::Error::FunctionFailed)
                }
                Ok(atr) => {
                    self.enabled = EnableState::Enabled(atr);
                    Ok(atr)
                }
            },
            EnableState::Enabled(atr) => Ok(atr),
            EnableState::Failed(_err) => Err(trussed::Error::FunctionFailed),
        }
    }

    fn reselect(&mut self) -> Result<Atr, trussed::Error> {
        match self.se.enable() {
            Err(err) => {
                error!("Reselecting failed: {:?}", err);
                self.enabled = EnableState::Failed(err);
                Err(trussed::Error::FunctionFailed)
            }
            Ok(atr) => {
                self.enabled = EnableState::Enabled(atr);
                Ok(atr)
            }
        }
    }

    fn configure(&mut self) -> Result<(), trussed::Error> {
        const REQUIRED_CURVES: [EcCurve; 2] = [EcCurve::NistP256, EcCurve::NistP521];
        self.enable()?;
        if self.configured {
            return Ok(());
        }
        let buf = &mut [0; 1024];
        let configured_curves = self
            .se
            .run_command(&ReadEcCurveList {}, buf)
            .map_err(|_err| {
                debug!("Failed to list curves: {_err:?}");
                trussed::Error::FunctionFailed
            })?;
        for i in REQUIRED_CURVES {
            if !configured_curves.ids.contains(&i.into()) {
                self.se.create_and_set_curve(i).map_err(|_err| {
                    debug!("Failed to create curve: {_err:?}");
                    trussed::Error::FunctionFailed
                })?;
            }
        }
        self.configured = true;

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
pub(crate) fn object_in_range(obj: ObjectId) -> bool {
    ID_RANGE.contains(&u32::from_be_bytes(obj.0))
}
