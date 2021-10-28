use askar_crypto::alg::{
    ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair, x25519::X25519KeyPair,
};

use crate::{
    did::{did_doc::VerificationMethodType, VerificationMaterial, VerificationMethod},
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwk::FromJwkValue,
    secrets::{Secret, SecretMaterial, SecretType},
    utils::crypto::{AsKnownKeyPair, KnownKeyAlg, KnownKeyPair},
};

pub(crate) fn is_did(did: &str) -> bool {
    let parts: Vec<String> = did.split(':').map(str::to_string).collect();
    return parts.len() >= 3 && parts.get(0).unwrap() == "did";
}

pub(crate) fn did_or_url(did_or_url: &str) -> (&str, Option<&str>) {
    // TODO: does it make sense to validate DID here?

    match did_or_url.split_once("#") {
        Some((did, _)) => (did, Some(did_or_url)),
        None => (did_or_url, None),
    }
}

impl AsKnownKeyPair for VerificationMethod {
    fn as_key_pair(&self) -> Result<KnownKeyPair> {
        match (&self.type_, &self.verification_material) {
            (VerificationMethodType::JsonWebKey2020, VerificationMaterial::JWK(ref jwk)) => {
                match (jwk["kty"].as_str(), jwk["crv"].as_str()) {
                    (Some(kty), Some(crv)) if kty == "EC" && crv == "P-256" => {
                        P256KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk") //TODO test
                            .map(KnownKeyPair::P256)
                    }
                    (Some(kty), Some(crv)) if kty == "EC" && crv == "secp256k1" => {
                        K256KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(KnownKeyPair::K256)
                    }
                    (Some(kty), Some(crv)) if kty == "OKP" && crv == "Ed25519" => {
                        Ed25519KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(KnownKeyPair::Ed25519)
                    }
                    (Some(kty), Some(crv)) if kty == "OKP" && crv == "X25519" => {
                        X25519KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(KnownKeyPair::X25519)
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

    fn key_alg(&self) -> KnownKeyAlg {
        match (&self.type_, &self.verification_material) {
            (VerificationMethodType::JsonWebKey2020, VerificationMaterial::JWK(ref jwk)) => {
                match (jwk["kty"].as_str(), jwk["crv"].as_str()) {
                    (Some(kty), Some(crv)) if kty == "EC" && crv == "P-256" => KnownKeyAlg::P256,
                    (Some(kty), Some(crv)) if kty == "EC" && crv == "secp256k1" => {
                        KnownKeyAlg::K256
                    }
                    (Some(kty), Some(crv)) if kty == "OKP" && crv == "Ed25519" => {
                        KnownKeyAlg::Ed25519
                    }
                    (Some(kty), Some(crv)) if kty == "OKP" && crv == "X25519" => {
                        KnownKeyAlg::X25519
                    }
                    _ => KnownKeyAlg::Unsupported,
                }
            }
            _ => KnownKeyAlg::Unsupported,
        }
    }
}

impl AsKnownKeyPair for Secret {
    fn as_key_pair(&self) -> Result<KnownKeyPair> {
        match (&self.type_, &self.secret_material) {
            (SecretType::JsonWebKey2020, SecretMaterial::JWK(ref jwk)) => {
                match (jwk["kty"].as_str(), jwk["crv"].as_str()) {
                    (Some(kty), Some(crv)) if kty == "EC" && crv == "P-256" => {
                        P256KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(KnownKeyPair::P256)
                    }
                    (Some(kty), Some(crv)) if kty == "EC" && crv == "secp256k1" => {
                        K256KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(KnownKeyPair::K256)
                    }
                    (Some(kty), Some(crv)) if kty == "OKP" && crv == "Ed25519" => {
                        Ed25519KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(KnownKeyPair::Ed25519)
                    }
                    (Some(kty), Some(crv)) if kty == "OKP" && crv == "X25519" => {
                        X25519KeyPair::from_jwk_value(jwk)
                            .kind(ErrorKind::Malformed, "Unable parse jwk")
                            .map(KnownKeyPair::X25519)
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

    fn key_alg(&self) -> KnownKeyAlg {
        match (&self.type_, &self.secret_material) {
            (SecretType::JsonWebKey2020, SecretMaterial::JWK(ref jwk)) => {
                match (jwk["kty"].as_str(), jwk["crv"].as_str()) {
                    (Some(kty), Some(crv)) if kty == "EC" && crv == "P-256" => KnownKeyAlg::P256,
                    (Some(kty), Some(crv)) if kty == "EC" && crv == "secp256k1" => {
                        KnownKeyAlg::K256
                    }
                    (Some(kty), Some(crv)) if kty == "OKP" && crv == "Ed25519" => {
                        KnownKeyAlg::Ed25519
                    }
                    (Some(kty), Some(crv)) if kty == "OKP" && crv == "X25519" => {
                        KnownKeyAlg::X25519
                    }
                    _ => KnownKeyAlg::Unsupported,
                }
            }
            _ => KnownKeyAlg::Unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::did::{did_or_url, is_did};

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

    #[test]
    fn is_did_works() {
        assert_eq!(is_did(""), false);
        assert_eq!(is_did("did:example:alice"), true);
        assert_eq!(is_did("did::"), true); //TODO is this ok?
        assert_eq!(is_did("example:example:alice"), false);
        assert_eq!(is_did("example:alice"), false);
    }
}
