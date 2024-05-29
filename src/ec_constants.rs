// Object identifiers in DER tag-length-value form
pub const OID_EC_PUBLIC_KEY_BYTES: &[u8] = &[
    /* RFC 5480 (id-ecPublicKey) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
];
pub const OID_SECP256R1_BYTES: &[u8] = &[
    /* RFC 5480 (secp256r1) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];
pub const OID_SECP384R1_BYTES: &[u8] = &[
    /* RFC 5480 (secp384r1) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x34,
];
pub const OID_SECP521R1_BYTES: &[u8] = &[
    /* RFC 5480 (secp521r1) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x35,
];

pub const OID_ED25519_BYTES: &[u8] = &[/* RFC 8410 (id-ed25519) */ 0x2b, 0x65, 0x70];
pub const OID_RS256_BYTES: &[u8] = &[
    /* RFC 4055 (sha256WithRSAEncryption) */
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
];

pub const OID_X25519_BYTES: &[u8] = &[
    /* https://tools.ietf.org/html/draft-josefsson-pkix-newcurves-01
     * 1.3.6.1.4.1.11591.15.1 */
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01,
];

pub const OID_ED25519_BYTES: &[u8] = &[
    /*
        https://oid-rep.orange-labs.fr/get/1.3.101.112
        A.1.  ASN.1 Object for Ed25519
        id-Ed25519 OBJECT IDENTIFIER ::= { 1.3.101.112 }
        Parameters are absent.  Length is 7 bytes.
        Binary encoding: 3005 0603 2B65 70

        The same algorithm identifiers are used for identifying a public key,
        a private key, and a signature (for the two EdDSA related OIDs).
        Additional encoding information is provided below for each of these
        locations.
    */
    0x2B, 0x65, 0x70,
];
