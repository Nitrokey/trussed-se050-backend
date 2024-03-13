use embedded_hal::blocking::delay::DelayUs;

use se05x::{
    se05x::{
        commands::{GetFreeMemory, GetVersion},
        Memory,
    },
    t1::I2CForT1,
};
use trussed::{
    serde_extensions::{Extension, ExtensionImpl},
    service::ServiceResources,
    types::Bytes,
    types::CoreContext,
    Error,
};
use trussed_se050_manage::{
    InfoReply, InfoRequest, ManageExtension, ManageRequest, TestSe050Reply,
};

use crate::Se050Backend;

impl<Twi: I2CForT1, D: DelayUs<u32>> ExtensionImpl<ManageExtension> for Se050Backend<Twi, D> {
    fn extension_request<P: trussed::Platform>(
        &mut self,
        _core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &<ManageExtension as Extension>::Request,
        _resources: &mut ServiceResources<P>,
    ) -> Result<<ManageExtension as Extension>::Reply, Error> {
        self.configure().map_err(|err| {
            debug!("Failed to enable for management: {err:?}");
            err
        })?;

        debug!("Runnig manage request: {request:?}");
        match request {
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
