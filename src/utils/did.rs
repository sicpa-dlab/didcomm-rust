use askar_crypto::alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair};
use serde_json::Value;

use crate::{
    did::{did_doc::VerificationMethodType, VerificationMaterial, VerificationMethod},
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwk::FromJwkValue,
    secrets::{Secret, SecretMaterial, SecretType},
    utils::crypto::SignKeyPair,
};

pub(crate) fn did_or_url(did_or_url: &str) -> (&str, Option<&str>) {
    // TODO: does it make sense to validate DID here?

    match did_or_url.split_once("#") {
        Some((did, _)) => (did, Some(did_or_url)),
        None => (did_or_url, None),
    }
}

pub(crate) trait ToSignKeyPair {
    fn to_sign_key_pair(&self) -> Result<SignKeyPair>;
}

impl ToSignKeyPair for VerificationMethod {
    fn to_sign_key_pair(&self) -> Result<SignKeyPair> {
        match (&self.type_, &self.verification_material) {
            (VerificationMethodType::JsonWebKey2020, VerificationMaterial::JWK(ref jwk)) => {
                match (&jwk["kty"], &jwk["crv"]) {
                    (Value::String(ref kty), Value::String(ref crv))
                        if kty == "EC" && crv == "P-256" =>
                    {
                        P256KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(SignKeyPair::P256KeyPair)
                    }
                    (Value::String(ref kty), Value::String(ref crv))
                        if kty == "EC" && crv == "secp256k1" =>
                    {
                        K256KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(SignKeyPair::K256KeyPair)
                    }
                    (Value::String(ref kty), Value::String(ref crv))
                        if kty == "OKP" && crv == "Ed25519" =>
                    {
                        Ed25519KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(SignKeyPair::Ed25519KeyPair)
                    }
                    _ => Err(err_msg(
                        ErrorKind::Unsupported,
                        "Unsupported key type or curve",
                    )),
                }
            }
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported verification method type and material combination",
            )),
        }
    }
}

impl ToSignKeyPair for Secret {
    fn to_sign_key_pair(&self) -> Result<SignKeyPair> {
        match (&self.type_, &self.secret_material) {
            (SecretType::JsonWebKey2020, SecretMaterial::JWK(ref jwk)) => {
                match (&jwk["kty"], &jwk["crv"]) {
                    (Value::String(ref kty), Value::String(ref crv))
                        if kty == "EC" && crv == "P-256" =>
                    {
                        P256KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(SignKeyPair::P256KeyPair)
                    }
                    (Value::String(ref kty), Value::String(ref crv))
                        if kty == "EC" && crv == "secp256k1" =>
                    {
                        K256KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(SignKeyPair::K256KeyPair)
                    }
                    (Value::String(ref kty), Value::String(ref crv))
                        if kty == "OKP" && crv == "Ed25519" =>
                    {
                        Ed25519KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(SignKeyPair::Ed25519KeyPair)
                    }
                    _ => Err(err_msg(
                        ErrorKind::Unsupported,
                        "Unsupported key type or curve",
                    )),
                }
            }
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported secret type and material",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::did::did_or_url;

    #[test]
    fn did_or_url_works() {
        let res = did_or_url("did:example:alice");
        assert_eq!(res, ("did:example:alice", None));

        let res = did_or_url("did:example:alice#key-1");
        assert_eq!(res, ("did:example:alice", Some("did:example:alice#key-1")));

        let res = did_or_url("#key-1");
        assert_eq!(res, ("", Some("#key-1")));

        let res = did_or_url("#");
        assert_eq!(res, ("", Some("#")));
    }
}
