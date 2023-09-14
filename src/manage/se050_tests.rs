use embedded_hal::blocking::delay::DelayUs;
use iso7816::Status;
use se05x::{
    se05x::{
        commands::{
            CreateSession, DeleteAll, DeleteSecureObject, EcdsaSign, EcdsaVerify, GetRandom,
            ReadIdList, ReadObject, VerifySessionUserId, WriteBinary, WriteEcKey, WriteUserId,
        },
        policies::{ObjectAccessRule, ObjectPolicyFlags, Policy, PolicySet},
        EcCurve, EcDsaSignatureAlgo, ObjectId, P1KeyType, ProcessSessionCmd, Se05XResult,
    },
    t1::I2CForT1,
};

use se05x::se05x::Se05X;
use trussed::Bytes;

use hex_literal::hex;

const BUFFER_LEN: usize = 1024;

#[derive(Debug)]
#[repr(u8)]
enum Advance {
    Enable = 1,
    Random1,
    Random2,
    Random3,
    WriteUserId,
    CreateSession,
    VerifySessionUserId,
    DeleteAll,
    List,
    WriteBinary1,
    ReadBinary1,
    DeleteBinary1,
    WriteBinary2,
    ReadBinary2,
    DeleteBinary2,
    WriteBinary3,
    ReadBinary3,
    DeleteBinary3,
    CreateP256,
    ListP256,
    GenerateP256,
    EcDsaP256,
    VerifyP256,
    DeleteP256,
    CreateP521,
    GenerateP521,
    EcDsaP521,
    VerifyP521,
    DeleteP521,
    RecreationWriteUserId,
    RecreationWriteBinary,
    RecreationDeleteAttempt,
    RecreationDeleteUserId,
    RecreationRecreateUserId,
    RecreationCreateSession,
    RecreationAuthSession,
    RecreationDeleteAttack,
    Rsa2048Gen,
    Rsa2048Sign,
    Rsa2048Verify,
    Rsa2048Encrypt,
    Rsa2048Decrypt,
    Rsa2048Delete,
    Rsa3072Gen,
    Rsa3072Sign,
    Rsa3072Verify,
    Rsa3072Encrypt,
    Rsa3072Decrypt,
    Rsa3072Delete,
    Rsa4096Gen,
    Rsa4096Sign,
    Rsa4096Verify,
    Rsa4096Encrypt,
    Rsa4096Decrypt,
    Rsa4096Delete,
    SymmWrite,
    SymmEncryptOneShot,
    SymmDecryptOneShot,
    SymmEncryptCreate,
    SymmEncryptInit,
    SymmEncryptUpdate1,
    SymmEncryptUpdate2,
    SymmEncryptFinal,
    SymmEncryptDelete,
    SymmDecryptCreate,
    SymmDecryptInit,
    SymmDecryptUpdate1,
    SymmDecryptUpdate2,
    SymmDecryptFinal,
    SymmDecryptDelete,
    SymmDelete,
    MacWrite,
    MacSignOneShot,
    MacVerifyOneShot,
    MacSignCreate,
    MacSignInit,
    MacSignUpdate1,
    MacSignUpdate2,
    MacSignFinal,
    MacSignDelete,
    MacVerifyCreate,
    MacVerifyInit,
    MacVerifyUpdate1,
    MacVerifyUpdate2,
    MacVerifyFinal,
    MacVerifyDelete,
    MacDelete,
    AesSessionCreateKey,
    AesSessionCreateBinary,
    AesSessionCreateSession,
    AesSessionAuthenticate,
    AesSessionReadBinary,
    AesSessionUpdateKey,
    AesSessionCloseSession,
    AesSessionRecreateSession,
    AesSessionReAuthenticate,
    AesSessionReadBinary2,
    AesSessionDeleteBinary,
    AesSessionDeleteKey,
    Pbkdf2WritePin,
    Pbkdf2Calculate,
    Pbkdf2Compare,
    Pbkdf2DeletePin,
    ImportWrite,
    ImportCipher,
    ImportExport,
    ImportDelete,
    ImportDeletionWorked,
    ImportImport,
    ImportCipher2,
    ImportComp,
    ImportDeleteFinal,
}

pub fn run_tests<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), trussed::Error> {
    debug_now!("Se05X run tests");
    match run_tests_internal(se050, response) {
        Ok(()) => Ok(()),
        Err(err) => {
            response.push(0).ok();
            let sw: [u8; 2] = err.into();
            response.extend_from_slice(&sw).ok();
            Ok(())
        }
    }
}
fn run_tests_internal<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    let atr = se050.enable()?;
    response
        .extend_from_slice(&[
            atr.major,
            atr.minor,
            atr.patch,
            atr.secure_box_major,
            atr.secure_box_minor,
        ])
        .ok();
    run_free_mem(se050, response)?;
    response.push(Advance::Enable as _).ok();
    run_get_random(se050, response)?;
    run_factory_reset(se050, response)?;
    run_list(se050, response)?;
    run_binary(se050, response)?;
    run_ecc(se050, response)?;
    run_userid_recreation(se050, response)?;
    run_rsa2048(se050, response)?;
    run_rsa3072(se050, response)?;
    run_rsa4096(se050, response)?;
    run_symm(se050, response)?;
    run_mac(se050, response)?;
    run_aes_session(se050, response)?;
    run_pbkdf(se050, response)?;
    run_export_import(se050, response)?;
    Ok(())
}

fn run_free_mem<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    use se05x::se05x::{commands::GetFreeMemory, Memory};

    let mut buf = [b'a'; BUFFER_LEN];
    let mem = se050.run_command(
        &GetFreeMemory {
            memory: Memory::Persistent,
        },
        &mut buf,
    )?;
    response
        .extend_from_slice(&mem.available.0.to_be_bytes())
        .ok();
    let mem = se050.run_command(
        &GetFreeMemory {
            memory: Memory::TransientReset,
        },
        &mut buf,
    )?;
    response
        .extend_from_slice(&mem.available.0.to_be_bytes())
        .ok();
    let mem = se050.run_command(
        &GetFreeMemory {
            memory: Memory::TransientDeselect,
        },
        &mut buf,
    )?;
    response
        .extend_from_slice(&mem.available.0.to_be_bytes())
        .ok();
    Ok(())
}

fn run_get_random<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    let mut buf = [b'a'; BUFFER_LEN];
    let lens = [1, 256, 800];
    let advance = [Advance::Random1, Advance::Random2, Advance::Random3];
    for (len, advance) in lens.into_iter().zip(advance) {
        let res = se050.run_command(
            &GetRandom {
                length: (len as u16).into(),
            },
            &mut buf,
        )?;
        response.push(advance as u8).ok();
        if res.data == &[b'a'; BUFFER_LEN][..len] {
            debug!("Failed to get random");
            response.extend_from_slice(&[0, 0, 0]).ok();
            return Ok(());
        }
    }
    Ok(())
}

fn run_factory_reset<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    let mut buf = [b'a'; BUFFER_LEN];
    let data = &hex!("31323334");

    se050.run_command(
        &WriteUserId {
            policy: None,
            max_attempts: None,
            object_id: ObjectId::FACTORY_RESET,
            data,
        },
        &mut buf,
    )?;
    response.push(Advance::WriteUserId as u8).ok();
    let session = se050.run_command(
        &CreateSession {
            object_id: ObjectId::FACTORY_RESET,
        },
        &mut buf,
    )?;
    response.push(Advance::CreateSession as u8).ok();

    se050.run_command(
        &ProcessSessionCmd {
            session_id: session.session_id,
            apdu: VerifySessionUserId { user_id: data },
        },
        &mut buf,
    )?;
    response.push(Advance::VerifySessionUserId as u8).ok();

    se050.run_command(
        &ProcessSessionCmd {
            session_id: session.session_id,
            apdu: DeleteAll {},
        },
        &mut buf,
    )?;
    response.push(Advance::DeleteAll as u8).ok();
    Ok(())
}

fn run_list<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    let mut buf = [0; 200];
    se050.run_command(
        &ReadIdList {
            offset: 0.into(),
            filter: se05x::se05x::SecureObjectFilter::All,
        },
        &mut buf,
    )?;
    response.push(Advance::List as u8).ok();
    Ok(())
}

fn run_binary<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    let mut buf = [b'a'; 400];
    let buf2 = [b'b'; 400];
    let object_id = ObjectId(hex!("01020304"));
    let policy = &[Policy {
        object_id: ObjectId::INVALID,
        access_rule: ObjectAccessRule::from_flags(
            ObjectPolicyFlags::ALLOW_DELETE | ObjectPolicyFlags::ALLOW_READ,
        ),
    }];
    for (((len, advance_write), advance_read), advance_delete) in [1, 255, 300]
        .into_iter()
        .zip([
            Advance::WriteBinary1,
            Advance::WriteBinary2,
            Advance::WriteBinary3,
        ])
        .zip([
            Advance::ReadBinary1,
            Advance::ReadBinary2,
            Advance::ReadBinary3,
        ])
        .zip([
            Advance::DeleteBinary1,
            Advance::DeleteBinary2,
            Advance::DeleteBinary3,
        ])
    {
        se050.run_command(
            &WriteBinary {
                transient: false,
                policy: Some(PolicySet(policy)),
                object_id,
                offset: None,
                file_length: Some(len.into()),
                data: Some(&buf2[..len.into()]),
            },
            &mut buf,
        )?;
        response.push(advance_write as u8).ok();
        let res = se050.run_command(
            &ReadObject {
                object_id,
                offset: None,
                length: Some(len.into()),
                rsa_key_component: None,
            },
            &mut buf,
        )?;
        response.push(advance_read as u8).ok();
        if res.data[..len.into()] != buf2[..len.into()] {
            return Err(0x3001.into());
        }

        se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
        response.push(advance_delete as u8).ok();
    }
    Ok(())
}

fn run_ecc<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    use se05x::se05x::commands::ReadEcCurveList;

    let mut buf = [0; 200];
    let mut buf2 = [0; 200];
    let object_id = ObjectId(hex!("01020304"));

    // *********** P256 *********** //

    se050.create_and_set_curve(EcCurve::NistP256)?;
    response.push(Advance::CreateP256 as u8).ok();
    let _res = se050.run_command(&ReadEcCurveList {}, &mut buf)?;
    debug_now!("Ec curves list: {:?}", _res);
    response.push(Advance::ListP256 as u8).ok();
    se050.run_command(
        &WriteEcKey {
            transient: false,
            is_auth: false,
            key_type: Some(P1KeyType::KeyPair),
            policy: None,
            max_attempts: None,
            object_id,
            curve: Some(EcCurve::NistP256),
            private_key: None,
            public_key: None,
        },
        &mut buf,
    )?;
    response.push(Advance::GenerateP256 as u8).ok();
    let res = se050.run_command(
        &EcdsaSign {
            key_id: object_id,
            data: &[52; 32],
            algo: EcDsaSignatureAlgo::Sha256,
        },
        &mut buf,
    )?;
    response.push(Advance::EcDsaP256 as u8).ok();
    let res = se050.run_command(
        &EcdsaVerify {
            key_id: object_id,
            data: &[52; 32],
            algo: EcDsaSignatureAlgo::Sha256,
            signature: res.signature,
        },
        &mut buf2,
    )?;
    if res.result != Se05XResult::Success {
        return Err(0x3002.into());
    }
    response.push(Advance::VerifyP256 as u8).ok();
    se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
    response.push(Advance::DeleteP256 as u8).ok();

    // *********** P521 *********** //

    se050.create_and_set_curve(EcCurve::NistP521)?;
    response.push(Advance::CreateP521 as u8).ok();
    se050.run_command(
        &WriteEcKey {
            transient: false,
            is_auth: false,
            key_type: Some(P1KeyType::KeyPair),
            policy: None,
            max_attempts: None,
            object_id,
            curve: Some(EcCurve::NistP521),
            private_key: None,
            public_key: None,
        },
        &mut buf,
    )?;
    response.push(Advance::GenerateP521 as u8).ok();
    let res = se050.run_command(
        &EcdsaSign {
            key_id: object_id,
            data: &[52; 64],
            algo: EcDsaSignatureAlgo::Sha512,
        },
        &mut buf,
    )?;
    response.push(Advance::EcDsaP521 as u8).ok();
    let res = se050.run_command(
        &EcdsaVerify {
            key_id: object_id,
            data: &[52; 64],
            algo: EcDsaSignatureAlgo::Sha512,
            signature: res.signature,
        },
        &mut buf2,
    )?;
    if res.result != Se05XResult::Success {
        return Err(0x3003.into());
    }
    response.push(Advance::VerifyP521 as u8).ok();
    se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
    response.push(Advance::DeleteP521 as u8).ok();
    Ok(())
}

fn run_userid_recreation<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    let mut buf = [0; BUFFER_LEN];
    let object_id = ObjectId(hex!("01020304"));
    let user_id = ObjectId(hex!("01223344"));
    let user_id_good_value = hex!("31323334");
    let user_id_bad_value = hex!("FFFFFFFF");
    let policy_user_id = &[Policy {
        object_id: ObjectId::INVALID,
        access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_DELETE),
    }];
    se050.run_command(
        &WriteUserId {
            policy: Some(PolicySet(policy_user_id)),
            max_attempts: None,
            object_id: user_id,
            data: &user_id_good_value,
        },
        &mut buf,
    )?;
    response.push(Advance::RecreationWriteUserId as u8).ok();
    let policy = &[Policy {
        object_id: user_id,
        access_rule: ObjectAccessRule::from_flags(
            ObjectPolicyFlags::ALLOW_DELETE | ObjectPolicyFlags::ALLOW_READ,
        ),
    }];
    se050.run_command(
        &WriteBinary {
            transient: false,
            policy: Some(PolicySet(policy)),
            object_id,
            offset: None,
            file_length: Some(2.into()),
            data: Some(&[1, 2]),
        },
        &mut buf,
    )?;
    response.push(Advance::RecreationWriteBinary as u8).ok();
    match se050.run_command(
        &ReadObject {
            object_id,
            offset: Some(0.into()),
            length: Some(2.into()),
            rsa_key_component: None,
        },
        &mut buf,
    ) {
        Ok(_) => return Err(0x3004.into()),
        Err(se05x::se05x::Error::Status(Status::CommandNotAllowedNoEf)) => {}
        Err(_err) => {
            debug_now!("Got unexpected error: {_err:?}");
            return Err(0x3007.into());
        }
    }
    response.push(Advance::RecreationDeleteAttempt as u8).ok();
    se050.run_command(&DeleteSecureObject { object_id: user_id }, &mut buf)?;
    response.push(Advance::RecreationDeleteUserId as u8).ok();
    se050.run_command(
        &WriteUserId {
            policy: None,
            max_attempts: None,
            object_id: user_id,
            data: &user_id_bad_value,
        },
        &mut buf,
    )?;
    response.push(Advance::RecreationRecreateUserId as u8).ok();

    let session = se050.run_command(&CreateSession { object_id: user_id }, &mut buf)?;
    response.push(Advance::RecreationCreateSession as u8).ok();

    se050.run_command(
        &ProcessSessionCmd {
            session_id: session.session_id,
            apdu: VerifySessionUserId {
                user_id: &user_id_bad_value,
            },
        },
        &mut buf,
    )?;
    response.push(Advance::RecreationAuthSession as u8).ok();

    let attack = se050.run_command(
        &ProcessSessionCmd {
            session_id: session.session_id,
            apdu: ReadObject {
                object_id,
                offset: Some(0.into()),
                length: Some(2.into()),
                rsa_key_component: None,
            },
        },
        &mut buf,
    );

    match attack {
        Ok(_) => {}
        Err(se05x::se05x::Error::Status(Status::CommandNotAllowedNoEf)) => {}
        Err(_err) => {
            debug_now!("Got unexpected error: {_err:?}");
            return Err(0x3006.into());
        }
    }
    response.push(Advance::RecreationDeleteAttack as u8).ok();
    Ok(())
}

fn run_rsa2048<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    use se05x::se05x::{
        commands::{GenRsaKey, RsaDecrypt, RsaEncrypt, RsaSign, RsaVerify},
        RsaEncryptionAlgo, RsaSignatureAlgo,
    };

    let mut buf = [0; 1000];
    let mut buf2 = [0; 1000];
    let object_id = ObjectId(hex!("02334455"));
    se050.run_command(
        &GenRsaKey {
            transient: false,
            is_auth: false,
            policy: None,
            max_attempts: None,
            object_id,
            key_size: Some(2048.into()),
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa2048Gen as u8).ok();
    let res = se050.run_command(
        &RsaSign {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa2048Sign as u8).ok();
    let res = se050.run_command(
        &RsaVerify {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
            signature: res.signature,
        },
        &mut buf2,
    )?;
    if res.result != Se05XResult::Success {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::Rsa2048Verify as u8).ok();
    let res = se050.run_command(
        &RsaEncrypt {
            key_id: object_id,
            plaintext: &[52; 32],
            algo: RsaEncryptionAlgo::Pkcs1,
        },
        &mut buf2,
    )?;
    response.push(Advance::Rsa2048Encrypt as u8).ok();
    let res = se050.run_command(
        &RsaDecrypt {
            key_id: object_id,
            algo: RsaEncryptionAlgo::Pkcs1,
            ciphertext: res.ciphertext,
        },
        &mut buf,
    )?;
    if res.plaintext != [52; 32] {
        return Err(0x3008.into());
    }
    response.push(Advance::Rsa2048Decrypt as u8).ok();

    se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
    response.push(Advance::Rsa2048Delete as u8).ok();

    Ok(())
}

fn run_rsa3072<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    use se05x::se05x::{
        commands::{GenRsaKey, RsaDecrypt, RsaEncrypt, RsaSign, RsaVerify},
        RsaEncryptionAlgo, RsaSignatureAlgo,
    };

    let mut buf = [0; 1000];
    let mut buf2 = [0; 1000];
    let object_id = ObjectId(hex!("02334455"));
    se050.run_command(
        &GenRsaKey {
            transient: false,
            is_auth: false,
            policy: None,
            max_attempts: None,
            object_id,
            key_size: Some(3072.into()),
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa3072Gen as u8).ok();
    let res = se050.run_command(
        &RsaSign {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa3072Sign as u8).ok();
    let res = se050.run_command(
        &RsaVerify {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
            signature: res.signature,
        },
        &mut buf2,
    )?;
    if res.result != Se05XResult::Success {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::Rsa3072Verify as u8).ok();
    let res = se050.run_command(
        &RsaEncrypt {
            key_id: object_id,
            plaintext: &[52; 32],
            algo: RsaEncryptionAlgo::Pkcs1,
        },
        &mut buf2,
    )?;
    response.push(Advance::Rsa3072Encrypt as u8).ok();
    let res = se050.run_command(
        &RsaDecrypt {
            key_id: object_id,
            algo: RsaEncryptionAlgo::Pkcs1,
            ciphertext: res.ciphertext,
        },
        &mut buf,
    )?;
    if res.plaintext != [52; 32] {
        return Err(0x3008.into());
    }
    response.push(Advance::Rsa3072Decrypt as u8).ok();

    se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
    response.push(Advance::Rsa3072Delete as u8).ok();

    Ok(())
}

fn run_rsa4096<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    use se05x::se05x::{
        commands::{GenRsaKey, RsaDecrypt, RsaEncrypt, RsaSign, RsaVerify},
        RsaEncryptionAlgo, RsaSignatureAlgo,
    };

    let mut buf = [0; 1000];
    let mut buf2 = [0; 1000];
    let object_id = ObjectId(hex!("02334455"));
    se050.run_command(
        &GenRsaKey {
            transient: false,
            is_auth: false,
            policy: None,
            max_attempts: None,
            object_id,
            key_size: Some(4096.into()),
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa4096Gen as u8).ok();
    let res = se050.run_command(
        &RsaSign {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa4096Sign as u8).ok();
    let res = se050.run_command(
        &RsaVerify {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
            signature: res.signature,
        },
        &mut buf2,
    )?;
    if res.result != Se05XResult::Success {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::Rsa4096Verify as u8).ok();
    let res = se050.run_command(
        &RsaEncrypt {
            key_id: object_id,
            plaintext: &[52; 32],
            algo: RsaEncryptionAlgo::Pkcs1,
        },
        &mut buf2,
    )?;
    response.push(Advance::Rsa4096Encrypt as u8).ok();
    let res = se050.run_command(
        &RsaDecrypt {
            key_id: object_id,
            algo: RsaEncryptionAlgo::Pkcs1,
            ciphertext: res.ciphertext,
        },
        &mut buf,
    )?;
    if res.plaintext != [52; 32] {
        return Err(0x3008.into());
    }
    response.push(Advance::Rsa4096Decrypt as u8).ok();

    se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
    response.push(Advance::Rsa4096Delete as u8).ok();

    Ok(())
}

fn run_symm<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    use se05x::se05x::{
        commands::{
            CipherDecryptInit, CipherEncryptInit, CipherFinal, CipherOneShotDecrypt,
            CipherOneShotEncrypt, CipherUpdate, CreateCipherObject, DeleteCryptoObj, WriteSymmKey,
        },
        CipherMode, CryptoObjectId, SymmKeyType,
    };

    let mut buf = [0; 1000];
    let mut buf2 = [0; 1000];
    let plaintext_data = [2; 32 * 15];
    let key_id = ObjectId(hex!("03445566"));
    let cipher_id = CryptoObjectId(hex!("0123"));
    let key = [0x42; 32];
    let iv = [0xFF; 16];
    se050.run_command(
        &WriteSymmKey {
            transient: true,
            is_auth: false,
            key_type: SymmKeyType::Aes,
            policy: None,
            max_attempts: None,
            object_id: key_id,
            kek_id: None,
            value: &key,
        },
        &mut buf,
    )?;
    response.push(Advance::SymmWrite as u8).ok();
    let ciphertext1 = se050.run_command(
        &CipherOneShotEncrypt {
            key_id,
            mode: CipherMode::AesCtr,
            plaintext: &plaintext_data,
            initialization_vector: Some(&iv),
        },
        &mut buf,
    )?;
    response.push(Advance::SymmEncryptOneShot as u8).ok();
    let plaintext1 = se050.run_command(
        &CipherOneShotDecrypt {
            key_id,
            mode: CipherMode::AesCtr,
            ciphertext: ciphertext1.ciphertext,
            initialization_vector: Some(&iv),
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmDecryptOneShot as u8).ok();
    assert_eq!(plaintext1.plaintext, plaintext_data);
    se050.run_command(
        &CreateCipherObject {
            id: cipher_id,
            subtype: CipherMode::AesCtr,
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmEncryptCreate as u8).ok();
    se050.run_command(
        &CipherEncryptInit {
            key_id,
            initialization_vector: Some(&iv),
            cipher_id,
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmEncryptInit as u8).ok();
    let ciphertext2 = se050.run_command(
        &CipherUpdate {
            cipher_id,
            data: &plaintext_data[0..32 * 10],
        },
        &mut buf2,
    )?;
    if ciphertext2.data != &ciphertext1.ciphertext[0..32 * 10] {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::SymmEncryptUpdate1 as u8).ok();
    let ciphertext3 = se050.run_command(
        &CipherUpdate {
            cipher_id,
            data: &plaintext_data[32 * 10..][..32 * 5],
        },
        &mut buf2,
    )?;
    if ciphertext3.data != &ciphertext1.ciphertext[32 * 10..][..32 * 5] {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::SymmEncryptUpdate2 as u8).ok();
    let ciphertext4 = se050.run_command(
        &CipherFinal {
            cipher_id,
            data: &plaintext_data[32 * 15..],
        },
        &mut buf2,
    )?;
    if ciphertext4.data != &ciphertext1.ciphertext[32 * 15..] {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::SymmEncryptFinal as u8).ok();
    se050.run_command(&DeleteCryptoObj { id: cipher_id }, &mut buf2)?;
    response.push(Advance::SymmEncryptDelete as u8).ok();
    se050.run_command(
        &CreateCipherObject {
            id: cipher_id,
            subtype: CipherMode::AesCtr,
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmDecryptCreate as u8).ok();
    se050.run_command(
        &CipherDecryptInit {
            key_id,
            initialization_vector: Some(&iv),
            cipher_id,
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmDecryptInit as u8).ok();
    let plaintext1 = se050.run_command(
        &CipherUpdate {
            cipher_id,
            data: &ciphertext1.ciphertext[0..32 * 10],
        },
        &mut buf2,
    )?;
    if plaintext1.data != &plaintext_data[..32 * 10] {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::SymmDecryptUpdate1 as u8).ok();
    let plaintext2 = se050.run_command(
        &CipherUpdate {
            cipher_id,
            data: &ciphertext1.ciphertext[32 * 10..][..32 * 5],
        },
        &mut buf2,
    )?;
    if plaintext2.data != &plaintext_data[32 * 10..][..32 * 5] {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::SymmDecryptUpdate2 as u8).ok();
    let plaintext3 = se050.run_command(
        &CipherFinal {
            cipher_id,
            data: &ciphertext1.ciphertext[32 * 15..],
        },
        &mut buf2,
    )?;
    if plaintext3.data != &plaintext_data[32 * 15..] {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::SymmDecryptFinal as u8).ok();
    se050.run_command(&DeleteCryptoObj { id: cipher_id }, &mut buf2)?;
    response.push(Advance::SymmDecryptDelete as u8).ok();
    se050.run_command(&DeleteSecureObject { object_id: key_id }, &mut buf2)?;
    response.push(Advance::SymmDelete as u8).ok();
    Ok(())
}

fn run_mac<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    use se05x::se05x::{
        commands::{
            CreateSignatureObject, DeleteCryptoObj, MacGenerateFinal, MacGenerateInit,
            MacOneShotGenerate, MacOneShotValidate, MacUpdate, MacValidateFinal, MacValidateInit,
            WriteSymmKey,
        },
        CryptoObjectId, MacAlgo, SymmKeyType,
    };

    let mut buf = [0; 1000];
    let mut buf2 = [0; 1000];
    let plaintext_data = [2; 32 * 15];
    let key_id = ObjectId(hex!("03445566"));
    let mac_id = CryptoObjectId(hex!("0123"));
    let key = [0x42; 32];
    se050.run_command(
        &WriteSymmKey {
            transient: false,
            is_auth: false,
            key_type: SymmKeyType::Hmac,
            policy: None,
            max_attempts: None,
            object_id: key_id,
            kek_id: None,
            value: &key,
        },
        &mut buf,
    )?;
    response.push(Advance::MacWrite as u8).ok();
    let tag1 = se050.run_command(
        &MacOneShotGenerate {
            key_id,
            data: &plaintext_data,
            algo: MacAlgo::HmacSha256,
        },
        &mut buf,
    )?;
    response.push(Advance::MacSignOneShot as u8).ok();
    let res = se050.run_command(
        &MacOneShotValidate {
            key_id,
            algo: MacAlgo::HmacSha256,
            data: &plaintext_data,
            tag: tag1.tag,
        },
        &mut buf2,
    )?;
    response.push(Advance::MacVerifyOneShot as u8).ok();
    if res.result != Se05XResult::Success {
        return Err((0x3000 + line!() as u16).into());
    }
    se050.run_command(
        &CreateSignatureObject {
            id: mac_id,
            subtype: MacAlgo::HmacSha256,
        },
        &mut buf2,
    )?;
    response.push(Advance::MacSignCreate as u8).ok();
    se050.run_command(&MacGenerateInit { key_id, mac_id }, &mut buf2)?;
    response.push(Advance::MacSignInit as u8).ok();
    se050.run_command(
        &MacUpdate {
            mac_id,
            data: &plaintext_data[0..32 * 10],
        },
        &mut buf2,
    )?;
    response.push(Advance::MacSignUpdate1 as u8).ok();
    se050.run_command(
        &MacUpdate {
            mac_id,
            data: &plaintext_data[32 * 10..][..32 * 5],
        },
        &mut buf2,
    )?;
    response.push(Advance::MacSignUpdate2 as u8).ok();
    let tag2 = se050.run_command(
        &MacGenerateFinal {
            mac_id,
            data: &plaintext_data[32 * 15..],
        },
        &mut buf2,
    )?;
    response.push(Advance::MacSignFinal as u8).ok();
    assert_eq!(tag2.tag, tag1.tag);
    se050.run_command(&DeleteCryptoObj { id: mac_id }, &mut buf)?;
    response.push(Advance::MacSignDelete as u8).ok();

    se050.run_command(
        &CreateSignatureObject {
            id: mac_id,
            subtype: MacAlgo::HmacSha256,
        },
        &mut buf,
    )?;
    response.push(Advance::MacVerifyCreate as u8).ok();
    se050.run_command(&MacValidateInit { key_id, mac_id }, &mut buf)?;
    response.push(Advance::MacVerifyInit as u8).ok();
    se050.run_command(
        &MacUpdate {
            mac_id,
            data: &plaintext_data[0..32 * 10],
        },
        &mut buf,
    )?;
    response.push(Advance::MacVerifyUpdate1 as u8).ok();
    se050.run_command(
        &MacUpdate {
            mac_id,
            data: &plaintext_data[32 * 10..][..32 * 5],
        },
        &mut buf,
    )?;
    response.push(Advance::MacVerifyUpdate2 as u8).ok();
    let res2 = se050.run_command(
        &MacValidateFinal {
            mac_id,
            data: &plaintext_data[32 * 15..],
            tag: tag2.tag,
        },
        &mut buf,
    )?;
    if res2.result != Se05XResult::Success {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::MacVerifyFinal as u8).ok();

    se050.run_command(&DeleteCryptoObj { id: mac_id }, &mut buf)?;
    response.push(Advance::MacVerifyDelete as u8).ok();

    se050.run_command(&DeleteSecureObject { object_id: key_id }, &mut buf2)?;
    response.push(Advance::MacDelete as u8).ok();
    Ok(())
}

fn run_aes_session<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    use rand_chacha::rand_core::SeedableRng;
    use se05x::se05x::{
        commands::{CloseSession, WriteSymmKey},
        SymmKeyType,
    };

    let mut buf = [0; 1024];
    let key = [0x42; 16];
    let key2 = [0x43; 16];
    let key_id = ObjectId(hex!("03445566"));
    let bin_id = ObjectId(hex!("03445567"));
    let bin_data = hex!("CAFECAFE");
    let key_policy = &[
        Policy {
            object_id: key_id,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_WRITE),
        },
        Policy {
            object_id: ObjectId::INVALID,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_DELETE),
        },
    ];
    let bin_policy = &[
        Policy {
            object_id: key_id,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_READ),
        },
        Policy {
            object_id: ObjectId::INVALID,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_DELETE),
        },
    ];
    se050.run_command(
        &WriteSymmKey {
            transient: false,
            is_auth: true,
            key_type: SymmKeyType::Aes,
            policy: Some(PolicySet(key_policy)),
            max_attempts: None,
            object_id: key_id,
            kek_id: None,
            value: &key,
        },
        &mut buf,
    )?;
    response.push(Advance::AesSessionCreateKey as _).ok();
    se050.run_command(
        &WriteBinary {
            transient: false,
            policy: Some(PolicySet(bin_policy)),
            object_id: bin_id,
            offset: None,
            file_length: Some((bin_data.len() as u16).into()),
            data: Some(&bin_data),
        },
        &mut buf,
    )?;
    response.push(Advance::AesSessionCreateBinary as _).ok();

    let session = se050.run_command(&CreateSession { object_id: key_id }, &mut buf)?;
    let session_id = session.session_id;
    response.push(Advance::AesSessionCreateSession as u8).ok();
    debug_now!("Created session");

    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0xCA; 32]);
    se050.authenticate_aes128_session(session_id, &key, &mut rng)?;
    response.push(Advance::AesSessionAuthenticate as u8).ok();

    let data = se050.run_command(
        &ProcessSessionCmd {
            session_id,
            apdu: ReadObject {
                object_id: bin_id,
                offset: None,
                length: Some((bin_data.len() as u16).into()),
                rsa_key_component: None,
            },
        },
        &mut buf,
    )?;
    assert_eq!(data.data, &bin_data);
    response.push(Advance::AesSessionReadBinary as _).ok();

    se050.run_command(
        &ProcessSessionCmd {
            session_id,
            apdu: WriteSymmKey {
                transient: false,
                is_auth: true,
                key_type: SymmKeyType::Aes,
                policy: None,
                max_attempts: None,
                object_id: key_id,
                kek_id: None,
                value: &key2,
            },
        },
        &mut buf,
    )?;
    response.push(Advance::AesSessionUpdateKey as _).ok();

    se050.run_command(
        &ProcessSessionCmd {
            session_id,
            apdu: CloseSession {},
        },
        &mut buf,
    )?;
    response.push(Advance::AesSessionCloseSession as _).ok();

    let session = se050.run_command(&CreateSession { object_id: key_id }, &mut buf)?;
    let session_id = session.session_id;
    response.push(Advance::AesSessionRecreateSession as u8).ok();
    debug_now!("Created session");

    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0xCA; 32]);
    se050.authenticate_aes128_session(session_id, &key2, &mut rng)?;
    response.push(Advance::AesSessionReAuthenticate as u8).ok();

    let data = se050.run_command(
        &ProcessSessionCmd {
            session_id,
            apdu: ReadObject {
                object_id: bin_id,
                offset: None,
                length: Some((bin_data.len() as u16).into()),
                rsa_key_component: None,
            },
        },
        &mut buf,
    )?;
    assert_eq!(data.data, &bin_data);
    response.push(Advance::AesSessionReadBinary2 as _).ok();

    se050.run_command(&DeleteSecureObject { object_id: bin_id }, &mut buf)?;
    response.push(Advance::AesSessionDeleteBinary as _).ok();
    se050.run_command(&DeleteSecureObject { object_id: key_id }, &mut buf)?;
    response.push(Advance::AesSessionDeleteKey as _).ok();

    Ok(())
}

fn run_pbkdf<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    use se05x::se05x::{
        commands::{Pbkdf2, WriteSymmKey},
        SymmKeyType,
    };

    let mut buf = [0; 1024];
    let pin = b"123456";
    let salt = [0x42; 16];
    let pin_id = ObjectId(hex!("03445566"));

    se050.run_command(
        &WriteSymmKey {
            transient: true,
            is_auth: false,
            key_type: SymmKeyType::Hmac,
            policy: None,
            max_attempts: None,
            object_id: pin_id,
            kek_id: None,
            value: pin,
        },
        &mut buf,
    )?;

    response.push(Advance::Pbkdf2WritePin as u8).ok();

    let res = se050.run_command(
        &Pbkdf2 {
            password: pin_id,
            salt: Some(&salt),
            iterations: 32.into(),
            requested_len: 16.into(),
        },
        &mut buf,
    )?;
    response.push(Advance::Pbkdf2Calculate as u8).ok();

    if res.data != hex!("685126241d909137ecd3385eaea2725f") {
        debug_now!("Got HASH: {:02x?}", res.data);
        return Err(Status::CorruptedData);
    }
    response.push(Advance::Pbkdf2Compare as u8).ok();

    se050.run_command(&DeleteSecureObject { object_id: pin_id }, &mut buf)?;
    response.push(Advance::Pbkdf2DeletePin as u8).ok();

    Ok(())
}

fn run_export_import<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se05X<Twi, D>,
    response: &mut Bytes<N>,
) -> Result<(), Status> {
    use se05x::se05x::{
        commands::{CipherOneShotEncrypt, ExportObject, ImportObject, WriteSymmKey},
        CipherMode, RsaKeyComponent, SymmKeyType,
    };

    let mut buf = [0; 128];
    let mut buf2 = [0; 1000];
    let mut buf3 = [0; 1000];
    let plaintext_data = [2; 32];
    let key_id = ObjectId(hex!("03445566"));
    let key = [0x42; 32];
    let iv = [0xFF; 16];
    let policy = &[
        Policy {
            object_id: ObjectId::INVALID,
            access_rule: ObjectAccessRule::from_flags(
                ObjectPolicyFlags::ALLOW_WRITE
                    | ObjectPolicyFlags::ALLOW_ENC
                    | ObjectPolicyFlags::ALLOW_DELETE
                    | ObjectPolicyFlags::ALLOW_IMPORT_EXPORT,
            ),
        },
        Policy {
            object_id: ObjectId::INVALID,
            access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_DELETE),
        },
    ];
    se050.run_command(
        &WriteSymmKey {
            transient: true,
            is_auth: false,
            key_type: SymmKeyType::Aes,
            policy: Some(PolicySet(policy)),
            max_attempts: None,
            object_id: key_id,
            kek_id: None,
            value: &key,
        },
        &mut buf,
    )?;
    response.push(Advance::ImportWrite as u8).ok();
    let ciphertext1 = se050.run_command(
        &CipherOneShotEncrypt {
            key_id,
            mode: CipherMode::AesCtr,
            plaintext: &plaintext_data,
            initialization_vector: Some(&iv),
        },
        &mut buf,
    )?;
    response.push(Advance::ImportCipher as u8).ok();

    debug_now!("Exporting");
    let exported = se050
        .run_command(
            &ExportObject {
                object_id: key_id,
                rsa_key_component: RsaKeyComponent::Na,
            },
            &mut buf2,
        )
        .map_err(|_err| {
            debug_now!("Got err: {:?}", _err);
            _err
        })?;
    response.push(Advance::ImportExport as u8).ok();

    se050.enable()?;
    response.push(Advance::ImportDelete as u8).ok();

    let res = se050.run_command(
        &CipherOneShotEncrypt {
            key_id,
            mode: CipherMode::AesCtr,
            plaintext: &plaintext_data,
            initialization_vector: Some(&iv),
        },
        &mut buf3,
    );
    if !matches!(
        res,
        Err(se05x::se05x::Error::Status(
            Status::ConditionsOfUseNotSatisfied,
        ))
    ) {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::ImportDeletionWorked as u8).ok();

    debug_now!("Importing");
    se050.run_command(
        &ImportObject {
            transient: true,
            object_id: key_id,
            rsa_key_component: None,
            serialized_object: exported.data,
        },
        &mut buf3,
    )?;
    response.push(Advance::ImportImport as u8).ok();

    debug_now!("Encrypting");
    let ciphertext2 = se050.run_command(
        &CipherOneShotEncrypt {
            key_id,
            mode: CipherMode::AesCtr,
            plaintext: &plaintext_data,
            initialization_vector: Some(&iv),
        },
        &mut buf3,
    )?;
    response.push(Advance::ImportCipher2 as u8).ok();

    debug_now!("Comparing");
    if ciphertext1.ciphertext != ciphertext2.ciphertext {
        return Err((0x3000 + line!() as u16).into());
    }
    response.push(Advance::ImportComp as u8).ok();

    se050.run_command(&DeleteSecureObject { object_id: key_id }, &mut buf3)?;
    response.push(Advance::ImportDeleteFinal as u8).ok();
    Ok(())
}
