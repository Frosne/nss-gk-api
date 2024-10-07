// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::err::{secstatus_to_res, Error, IntoResult};
use crate::init;

use crate::p11::PK11_ExportDERPrivateKeyInfo;
use crate::p11::PK11_ImportDERPrivateKeyInfoAndReturnKey;
use crate::p11::PK11_PubDeriveWithKDF;
use crate::p11::SECKEY_DecodeDERSubjectPublicKeyInfo;
use crate::p11::PK11_SignatureLen;
use crate::p11::Slot;

use crate::PrivateKey;
use crate::PublicKey;
use crate::SECItem;
use crate::SECItemBorrowed;

use std::ptr::null_mut;


pub fn export_ec_private_key_pkcs8(key: PrivateKey) -> Result<Vec<u8>, Error> {
    unsafe {
        let sk = PK11_ExportDERPrivateKeyInfo(*key, null_mut())
            .into_result()
            .unwrap();
        return Ok(sk.into_vec());
    }
}

pub fn import_ec_private_key_pkcs8(pki: &[u8]) -> Result<PrivateKey, Error> {
    let slot = Slot::internal()?;

    let mut der_pki = SECItemBorrowed::wrap(&pki);
    let der_pki_ptr: *mut SECItem = der_pki.as_mut();
    
    let mut pk_ptr = null_mut();

    unsafe {
        secstatus_to_res(PK11_ImportDERPrivateKeyInfoAndReturnKey(
            *slot,
            der_pki_ptr,
            null_mut(),
            null_mut(),
            0,
            0,
            crate::p11::KU_ALL,
            &mut pk_ptr,
            null_mut(),
        ))
        .expect("PKCS8 encoded key import has failed");

        let sk = PrivateKey::from_ptr(pk_ptr)?;
        Ok(sk)
    }
}


pub fn import_ec_public_key_spki(spki: &[u8]) -> Result<PublicKey, Error> {
    let mut spki_item = SECItemBorrowed::wrap(&spki);
    let spki_item_ptr = spki_item.as_mut();

    unsafe {
        let spki = SECKEY_DecodeDERSubjectPublicKeyInfo(spki_item_ptr)
            .into_result()
            .unwrap();
        let pk = crate::p11::SECKEY_ExtractPublicKey(spki.as_mut().unwrap())
            .into_result()
            .unwrap();
        Ok(pk)
    }
}

pub fn ecdh(sk: PrivateKey, pk: PublicKey) -> Result<Vec<u8>, Error> {
    let sym_key = unsafe {
        PK11_PubDeriveWithKDF(
            sk.cast(),
            pk.cast(),
            0,
            null_mut(),
            null_mut(),
            pkcs11_bindings::CKM_ECDH1_DERIVE,
            pkcs11_bindings::CKM_SHA512_HMAC,
            pkcs11_bindings::CKA_SIGN,
            0,
            pkcs11_bindings::CKD_NULL,
            null_mut(),
            null_mut(),
        )
        .into_result()?
    };

    let key = sym_key.as_bytes().unwrap();
    Ok(key.to_vec())
}

pub fn convert_to_public(sk: PrivateKey) -> Result<PublicKey, Error> {
    unsafe {
        let pk = crate::p11::SECKEY_ConvertToPublicKey(*sk).into_result()?;
        Ok(pk)
    }
}

pub fn sign(
    private_key: PrivateKey,
    data: &[u8],
    mechanism: std::os::raw::c_ulong,
) -> Result<Vec<u8>, Error> {
    let mut data_to_sign = SECItemBorrowed::wrap(&data);

    unsafe {
        let signature_len = PK11_SignatureLen(*private_key);
        let data_signature = vec![0u8; signature_len as usize];
        let mut signature = SECItemBorrowed::wrap(&data_signature);

        secstatus_to_res(crate::p11::PK11_SignWithMechanism(
            private_key.as_mut().unwrap(),
            mechanism,
            null_mut(),
            signature.as_mut(),
            data_to_sign.as_mut(),
        ))
        .expect("Signature has failed");

        let signature = signature.as_slice().to_vec();
        Ok(signature)
    }
}

pub fn sign_ecdsa(private_key: PrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    sign(private_key, data, crate::p11::CKM_ECDSA.into())
}

pub fn sign_eddsa(private_key: PrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    sign(private_key, data, crate::p11::CKM_EDDSA.into())
}

pub fn verify(
    public_key: PublicKey,
    data: &[u8],
    signature: &[u8],
    mechanism: std::os::raw::c_ulong,
) -> Result<bool, Error> {
    unsafe {
        let mut data_to_sign = SECItemBorrowed::wrap(&data);
        let mut signature = SECItemBorrowed::wrap(&signature);

        let rv = crate::p11::PK11_VerifyWithMechanism(
            public_key.as_mut().unwrap(),
            mechanism.into(),
            null_mut(),
            signature.as_mut(),
            data_to_sign.as_mut(),
            null_mut(),
        );

        match rv {
            0 => Ok(true),
            _ => Ok(false),
        }
    }
}

pub fn verify_ecdsa(public_key: PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
    verify(public_key, data, signature, crate::p11::CKM_ECDSA.into())
}

pub fn verify_eddsa(public_key: PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
    verify(public_key, data, signature, crate::p11::CKM_EDDSA.into())
}
