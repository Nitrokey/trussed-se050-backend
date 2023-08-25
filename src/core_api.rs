//! Implementations of the core APIs for the SE050 backend

use embedded_hal::blocking::delay::DelayUs;
use littlefs2::path::PathBuf;
use se05x::{se05x::commands::GetRandom, t1::I2CForT1};
use trussed::{
    api::{reply, request, Request},
    backend::Backend,
    config::MAX_MESSAGE_LENGTH,
    types::{Mechanism, Message},
};

use crate::{Context, Se050Backend, BACKEND_DIR};

const BUFFER_LEN: usize = 2048;
const CORE_DIR: &str = "se050-core";

impl<Twi: I2CForT1, D: DelayUs<u32>> Se050Backend<Twi, D> {
    fn random_bytes(&mut self, count: usize) -> Result<trussed::Reply, trussed::Error> {
        if count >= MAX_MESSAGE_LENGTH {
            return Err(trussed::Error::MechanismParamInvalid);
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

fn supported(mechanism: Mechanism) -> bool {
    matches!(mechanism, |Mechanism::Ed255| Mechanism::P256
        | Mechanism::P256Prehashed
        | Mechanism::X255
        | Mechanism::Rsa2048Raw
        | Mechanism::Rsa3072Raw
        | Mechanism::Rsa4096Raw
        | Mechanism::Rsa2048Pkcs1v15
        | Mechanism::Rsa3072Pkcs1v15
        | Mechanism::Rsa4096Pkcs1v15)
}

impl<Twi: I2CForT1, D: DelayUs<u32>> Backend for Se050Backend<Twi, D> {
    type Context = Context;

    fn request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut trussed::types::CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, trussed::Error> {
        self.enable()?;
        debug_now!("Trussed Auth request: {request:?}");

        // FIXME: Have a real implementation from trussed
        let mut backend_path = core_ctx.path.clone();
        backend_path.push(&PathBuf::from(BACKEND_DIR));
        backend_path.push(&PathBuf::from(CORE_DIR));
        let _fs = &mut resources.filestore(backend_path);
        let _global_fs = &mut resources.filestore(PathBuf::from(BACKEND_DIR));
        let _rng = &mut resources.rng()?;
        let _client_id = core_ctx.path.clone();
        let _keystore = &mut resources.keystore(core_ctx)?;

        match request {
            Request::RandomBytes(request::RandomBytes { count }) => self.random_bytes(*count),
            Request::Agree(req) if supported(req.mechanism) => todo!(),
            Request::Decrypt(req) if supported(req.mechanism) => todo!(),
            Request::DeriveKey(req) if supported(req.mechanism) => todo!(),
            Request::DeserializeKey(req) if supported(req.mechanism) => todo!(),
            Request::Encrypt(req) if supported(req.mechanism) => todo!(),
            Request::Delete(_req) => todo!(),
            Request::DeleteAllKeys(_req) => todo!(),
            Request::Exists(req) if supported(req.mechanism) => todo!(),
            Request::GenerateKey(req) if supported(req.mechanism) => todo!(),
            Request::GenerateSecretKey(_req) => todo!(),
            Request::SerializeKey(req) if supported(req.mechanism) => todo!(),
            Request::Sign(req) if supported(req.mechanism) => todo!(),
            Request::UnsafeInjectKey(req) if supported(req.mechanism) => todo!(),
            Request::UnsafeInjectSharedKey(_req) => todo!(),
            Request::UnwrapKey(req) if supported(req.mechanism) => todo!(),
            Request::Verify(req) if supported(req.mechanism) => todo!(),
            Request::WrapKey(req) if supported(req.mechanism) => todo!(),

            _ => Err(trussed::Error::RequestNotAvailable),
        }
    }
}
