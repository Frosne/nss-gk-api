// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::der;
use crate::err::IntoResult;
use crate::init;
use crate::p11::{PrivateKey, PublicKey};
use crate::Error;
use std::ptr;

use crate::p11::PK11_GenerateKeyPairWithOpFlags;
use crate::p11::Slot;
use crate::p11::PK11_ATTR_EXTRACTABLE;
use crate::p11::PK11_ATTR_INSENSITIVE;
use crate::p11::PK11_ATTR_SESSION;
use crate::SECItem;
use crate::SECItemBorrowed;
use pkcs11_bindings::CKF_DERIVE;
use pkcs11_bindings::CKM_EC_EDWARDS_KEY_PAIR_GEN;
use pkcs11_bindings::CKM_EC_KEY_PAIR_GEN;
use pkcs11_bindings::CKM_EC_MONTGOMERY_KEY_PAIR_GEN;



pub enum EcCurve {
    P256,
    P384,
    P521,
    X25519,
    Ed25519,
}


pub fn object_id(val: &[u8]) -> Result<Vec<u8>, crate::Error> {
    let mut out = Vec::with_capacity(der::MAX_TAG_AND_LENGTH_BYTES + val.len());
    der::write_tag_and_length(&mut out, der::TAG_OBJECT_ID, val.len())?;
    out.extend_from_slice(val);
    Ok(out)
}

fn ec_curve_to_oid(alg: &EcCurve) -> Result<Vec<u8>, Error> {
    match alg {
        EcCurve::X25519 => Ok(OID_X25519_BYTES.to_vec()),
        EcCurve::Ed25519 => Ok(OID_ED25519_BYTES.to_vec()),
        EcCurve::P256 => Ok(OID_SECP256R1_BYTES.to_vec()),
        EcCurve::P384 => Ok(OID_SECP384R1_BYTES.to_vec()),
        EcCurve::P521 => Ok(OID_SECP521R1_BYTES.to_vec()),
    }
}

fn ec_curve_to_ckm(alg: &EcCurve) -> pkcs11_bindings::CK_MECHANISM_TYPE {
    match alg {
        EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => CKM_EC_KEY_PAIR_GEN.into(),
        EcCurve::Ed25519 => CKM_EC_EDWARDS_KEY_PAIR_GEN.into(), // todo
        EcCurve::X25519 => CKM_EC_MONTGOMERY_KEY_PAIR_GEN.into(), //todo
    }
}

fn curve_supports_derivation(curve: EcCurve) -> bool
{
    match curve{
        EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => true,
        EcCurve::Ed25519 => false,
        EcCurve::X25519 => true,
    }
}

fn curve_supports_signature(curve: EcCurve) -> bool
{
    match curve{
        EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => true,
        EcCurve::Ed25519 => true,
        EcCurve::X25519 => false,
    }
}

pub fn generate_sign_keys(alg: EcCurve) -> Result<(PrivateKey, PublicKey), crate::Error>
{
    if (!curve_supports_signature(curve))
    {
        panic!("Does not support key signature");
    }
    return generate_eckey(EcCurve, CKF_SIGN);
}

pub fn generate_derive_keys(curve: EcCurve) -> Result<(PrivateKey, PublicKey), crate::Error>
{
    if (!curve_supports_derivation(curve))
    {
        panic!("Does not support key derivation");
    }

    return generate_eckey(curve, CKF_DERIVE);
}


// Main private function
fn generate_eckey(curve: EcCurve, flags: uint32) -> Result<(PrivateKey, PublicKey), crate::Error> {
    
    if (!nss::NSS_IsInitialized)
    {
        panic!("NSS is not initialised.");
    }

    // Get the OID for the Curve
    let curve_oid = ec_curve_to_oid(&curve)?;
    let oid_bytes = object_id(&curve_oid)?;
    let mut oid = SECItemBorrowed::wrap(&oid_bytes);
    let oid_ptr: *mut SECItem = oid.as_mut();

    // Get the Mechanism based on the Curve and its use
    let ckm = ec_curve_to_ckm(&curve);

    // Get the PKCS11 slot
    let slot = Slot::internal()?;

    // Create a pointer for the public key
    let mut pk_ptr = ptr::null_mut();

    // https://github.com/mozilla/nss-gk-api/issues/1
    unsafe {
        let sk =
            // Type of `param` argument depends on mechanism. For EC keygen it is
            // `SECKEYECParams *` which is a typedef for `SECItem *`.
            PK11_GenerateKeyPairWithOpFlags(
                *slot,
                ckm,
                oid_ptr.cast(),
                &mut pk_ptr,
                PK11_ATTR_EXTRACTABLE | PK11_ATTR_INSENSITIVE | PK11_ATTR_SESSION,
                flags,
                flags,
                ptr::null_mut(),
            )
            .into_result()?;

        let pk = PublicKey::from_ptr(pk_ptr)?;

        Ok((sk, pk))
    }
}
