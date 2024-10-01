use core::ops::Deref;

use chacha20poly1305::{aead, AeadInPlace, ChaCha8Poly1305, KeyInit};

type HkdfSha256 = hkdf::Hkdf<sha2::Sha256>;
type HkdfSha256Extract = hkdf::HkdfExtract<sha2::Sha256>;

const X25519_KEM_SUITE_ID: &[u8] = b"KEM\x00\x20";
const X25519_HKDF_CHACHA8POLY1305_HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x20\x00\x01\xFF\xFE";
const MODE_BASE: u8 = 0x00;
const NK: usize = 32;
const NN: usize = 12;
const NH: usize = 32;

pub const TAG_LEN: usize = 16;

fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> (HkdfSha256, [u8; 32]) {
    let mut extract_ctx = HkdfSha256Extract::new(Some(salt));
    extract_ctx.input_ikm(b"HPKE-v1");
    extract_ctx.input_ikm(suite_id);
    extract_ctx.input_ikm(label);
    extract_ctx.input_ikm(ikm);
    let (prk, hkdf) = extract_ctx.finalize();
    (hkdf, prk.into())
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &HkdfSha256,
    label: &[u8],
    info: &[u8],
    buffer: &mut [u8],
) -> Result<(), hkdf::InvalidLength> {
    let Ok(l): Result<u16, _> = buffer.len().try_into() else {
        return Err(hkdf::InvalidLength);
    };
    prk.expand_multi_info(
        &[&l.to_be_bytes(), b"HPKE-v1", suite_id, label, info],
        buffer,
    )
}

pub struct SharedSecret([u8; 32]);
pub struct PublicKey([u8; 32]);

impl TryFrom<&[u8]> for SharedSecret {
    type Error = trussed::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(
            value
                .try_into()
                .map_err(|_| trussed::Error::InternalError)?,
        ))
    }
}

impl From<[u8; 32]> for SharedSecret {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl Deref for SharedSecret {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = trussed::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(
            value
                .try_into()
                .map_err(|_| trussed::Error::InternalError)?,
        ))
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl Deref for PublicKey {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn extract_and_expand(dh: SharedSecret, kem_context: &[u8]) -> [u8; 32] {
    let (prk, _) = labeled_extract(X25519_KEM_SUITE_ID, b"", b"eae_prk", &dh.0);
    let mut shr = [0; 32];
    labeled_expand(
        X25519_KEM_SUITE_ID,
        &prk,
        b"shared_secret",
        kem_context,
        &mut shr,
    )
    .expect("Length of shr is known to be OK");
    shr
}

pub struct Context {
    key: [u8; NK],
    base_nonce: [u8; NN],
    /// Used only in tests for comparison with the test vectors
    #[allow(unused)]
    exporter_secret: [u8; NH],
    // Our limited version only allows one encryption/decryption
    // seq: u128,
}

impl Context {
    pub fn seal_in_place_detached(self, aad: &[u8], plaintext: &mut [u8]) -> [u8; TAG_LEN] {
        // We don't increment because the simplified API only allows 1 encryption
        let nonce = (&self.base_nonce).into();
        let aead = ChaCha8Poly1305::new((&self.key).into());
        let tag = aead
            .encrypt_in_place_detached(nonce, aad, plaintext)
            .expect("Not used to encrypt data too large");

        tag.into()
    }

    pub fn open_in_place_detached(
        self,
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: [u8; TAG_LEN],
    ) -> Result<(), aead::Error> {
        let nonce = (&self.base_nonce).into();
        let aead = ChaCha8Poly1305::new((&self.key).into());
        aead.decrypt_in_place_detached(nonce, aad, ciphertext, (&tag).into())
    }
}

pub fn key_schedule(shared_secret: SharedSecret, info: &[u8]) -> Context {
    let (_, psk_id_hash) = labeled_extract(
        X25519_HKDF_CHACHA8POLY1305_HPKE_SUITE_ID,
        b"",
        b"psk_id_hash",
        b"",
    );
    let (_, info_hash) = labeled_extract(
        X25519_HKDF_CHACHA8POLY1305_HPKE_SUITE_ID,
        b"",
        b"info_hash",
        info,
    );
    let mut key_schedule_context = [0; 65];
    key_schedule_context[0] = MODE_BASE;
    key_schedule_context[1..33].copy_from_slice(&psk_id_hash);
    key_schedule_context[33..].copy_from_slice(&info_hash);
    let (secret, _) = labeled_extract(
        X25519_HKDF_CHACHA8POLY1305_HPKE_SUITE_ID,
        &*shared_secret,
        b"secret",
        b"",
    );
    let mut key = [0; NK];
    labeled_expand(
        X25519_HKDF_CHACHA8POLY1305_HPKE_SUITE_ID,
        &secret,
        b"key",
        &key_schedule_context,
        &mut key,
    )
    .expect("KEY is not too large");
    let mut base_nonce = [0; NN];
    labeled_expand(
        X25519_HKDF_CHACHA8POLY1305_HPKE_SUITE_ID,
        &secret,
        b"base_nonce",
        &key_schedule_context,
        &mut base_nonce,
    )
    .expect("NONCE is not too large");
    let mut exporter_secret = [0; NH];
    labeled_expand(
        X25519_HKDF_CHACHA8POLY1305_HPKE_SUITE_ID,
        &secret,
        b"exp",
        &key_schedule_context,
        &mut exporter_secret,
    )
    .expect("EXP is not too large");
    Context {
        key,
        base_nonce,
        exporter_secret,
    }
}
