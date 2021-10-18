/// Algorithms for anonymous encryption
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AnonCryptAlg {
    /// AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    A256cbcHs512EcdhEsA256kw,

    /// XChaCha20Poly1305 with a 256 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    Xc20pEcdhEsA256kw,

    /// A256GCM_ECDH_ES_A256KW: XChaCha20Poly1305 with a 256 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    A256gcmEcdhEsA256kw,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AuthCryptAlg {
    /// AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-1PU key agreement with A256KW key wrapping
    A256cbcHs512Ecdh1puA256kw,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignAlg {
    EdDSA,
    ES256,
    ES256K,
}
