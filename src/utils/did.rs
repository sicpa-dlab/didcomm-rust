use askar_crypto::alg::{
    ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair, x25519::X25519KeyPair,
};
use base58::FromBase58;
use serde_json::json;
use std::io::Cursor;
use varint::{VarintRead, VarintWrite};

use crate::{
    did::{did_doc::VerificationMethodType, VerificationMaterial, VerificationMethod},
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwk::FromJwkValue,
    secrets::{Secret, SecretMaterial, SecretType},
    utils::crypto::{AsKnownKeyPair, KnownKeyAlg, KnownKeyPair},
};

pub(crate) fn is_did(did: &str) -> bool {
    let parts: Vec<_> = did.split(':').collect();
    return parts.len() >= 3 && parts.get(0).unwrap() == &"did";
}

pub(crate) fn did_or_url(did_or_url: &str) -> (&str, Option<&str>) {
    // TODO: does it make sense to validate DID here?

    match did_or_url.split_once("#") {
        Some((did, _)) => (did, Some(did_or_url)),
        None => (did_or_url, None),
    }
}

impl AsKnownKeyPair for VerificationMethod {
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

    fn as_key_pair(&self) -> Result<KnownKeyPair> {
        match (&self.type_, &self.verification_material) {
            (VerificationMethodType::JsonWebKey2020, VerificationMaterial::JWK(ref jwk)) => {
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

            (
                VerificationMethodType::X25519KeyAgreementKey2019,
                VerificationMaterial::Base58(ref b58_value),
            ) => {
                let decoded_value = b58_value.from_base58().map_err(|_e| {
                    err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong base58 value in verification material",
                    )
                })?;
                let base64_url_value =
                    base64::encode_config(&decoded_value, base64::URL_SAFE_NO_PAD);

                let jwk = json!({
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": base64_url_value
                });

                X25519KeyPair::from_jwk_value(&jwk)
                    .kind(
                        ErrorKind::Malformed,
                        "Unable parse base58 verification material",
                    )
                    .map(KnownKeyPair::X25519)
            }

            (
                VerificationMethodType::Ed25519VerificationKey2018,
                VerificationMaterial::Base58(ref b58_value),
            ) => {
                let decoded_value = b58_value.from_base58().map_err(|_e| {
                    err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong base58 value in verification material",
                    )
                })?;
                let base64_url_value =
                    base64::encode_config(&decoded_value, base64::URL_SAFE_NO_PAD);

                let jwk = json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64_url_value
                });

                Ed25519KeyPair::from_jwk_value(&jwk)
                    .kind(
                        ErrorKind::Malformed,
                        "Unable parse base58 verification material",
                    )
                    .map(KnownKeyPair::Ed25519)
            }

            (
                VerificationMethodType::X25519KeyAgreementKey2020,
                VerificationMaterial::Multibase(ref multibase_value),
            ) => {
                if !multibase_value.starts_with('z') {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Multibase value must start with 'z'",
                    ))?
                };
                let decoded_value = multibase_value.split_at(1).1.from_base58().map_err(|_e| {
                    err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong multibase value in verification material",
                    )
                })?;

                let (codec, decoded_value) = _from_multicodec(&decoded_value)?;
                if codec != Codec::X25519Pub {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong codec in multibase secret material",
                    ))?
                }
                let base64_url_value =
                    base64::encode_config(&decoded_value, base64::URL_SAFE_NO_PAD);

                let jwk = json!({
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": base64_url_value
                });

                X25519KeyPair::from_jwk_value(&jwk)
                    .kind(
                        ErrorKind::Malformed,
                        "Unable parse multibase verification material",
                    )
                    .map(KnownKeyPair::X25519)
            }

            (
                VerificationMethodType::Ed25519VerificationKey2020,
                VerificationMaterial::Multibase(ref multibase_value),
            ) => {
                if !multibase_value.starts_with('z') {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Multibase must start with 'z'",
                    ))?
                }
                let decoded_value = multibase_value.split_at(1).1.from_base58().map_err(|_e| {
                    err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong multibase value in verification material",
                    )
                })?;

                let (codec, decoded_value) = _from_multicodec(&decoded_value)?;
                if codec != Codec::Ed25519Pub {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong codec in multibase secret material",
                    ))?
                }
                let base64_url_value =
                    base64::encode_config(&decoded_value, base64::URL_SAFE_NO_PAD);

                let jwk = json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64_url_value
                });

                Ed25519KeyPair::from_jwk_value(&jwk)
                    .kind(
                        ErrorKind::Malformed,
                        "Unable parse multibase verification material",
                    )
                    .map(KnownKeyPair::Ed25519)
            }
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported verification method type and material combination",
            )),
        }
    }
}

impl AsKnownKeyPair for Secret {
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

            (SecretType::X25519KeyAgreementKey2019, SecretMaterial::Base58(ref b58_value)) => {
                let decoded_value = b58_value.from_base58().map_err(|_e| {
                    err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong base58 value in secret material",
                    )
                })?;

                let curve25519_point_size = 32;
                let (d_value, x_value) = decoded_value.split_at(curve25519_point_size);
                let base64_url_d_value = base64::encode_config(&d_value, base64::URL_SAFE_NO_PAD);
                let base64_url_x_value = base64::encode_config(&x_value, base64::URL_SAFE_NO_PAD);

                let jwk = json!({
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": base64_url_x_value,
                    "d": base64_url_d_value
                });

                X25519KeyPair::from_jwk_value(&jwk)
                    .kind(ErrorKind::Malformed, "Unable parse base58 secret material")
                    .map(KnownKeyPair::X25519)
            }

            (SecretType::Ed25519VerificationKey2018, SecretMaterial::Base58(ref b58_value)) => {
                let decoded_value = b58_value.from_base58().map_err(|_e| {
                    err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong base58 value in secret material",
                    )
                })?;

                let curve25519_point_size = 32;
                let (d_value, x_value) = decoded_value.split_at(curve25519_point_size);
                let base64_url_d_value = base64::encode_config(&d_value, base64::URL_SAFE_NO_PAD);
                let base64_url_x_value = base64::encode_config(&x_value, base64::URL_SAFE_NO_PAD);

                let jwk = json!({"kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64_url_x_value,
                    "d": base64_url_d_value
                });

                Ed25519KeyPair::from_jwk_value(&jwk)
                    .kind(ErrorKind::Malformed, "Unable parse base58 secret material")
                    .map(KnownKeyPair::Ed25519)
            }

            (
                SecretType::X25519KeyAgreementKey2020,
                SecretMaterial::Multibase(ref multibase_value),
            ) => {
                if !multibase_value.starts_with('z') {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Multibase must start with 'z'",
                    ))?
                }
                let decoded_multibase_value =
                    multibase_value.split_at(1).1.from_base58().map_err(|_e| {
                        err_msg(
                            ErrorKind::IllegalArgument,
                            "Wrong multibase value in secret material",
                        )
                    })?;

                let (codec, decoded_value) = _from_multicodec(&decoded_multibase_value)?;
                if codec != Codec::X25519Priv {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong codec in multibase secret material",
                    ))?
                }

                let curve25519_point_size = 32;
                let (d_value, x_value) = decoded_value.split_at(curve25519_point_size);
                let base64_url_d_value = base64::encode_config(&d_value, base64::URL_SAFE_NO_PAD);
                let base64_url_x_value = base64::encode_config(&x_value, base64::URL_SAFE_NO_PAD);

                let jwk = json!({
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": base64_url_x_value,
                    "d": base64_url_d_value
                });

                X25519KeyPair::from_jwk_value(&jwk)
                    .kind(
                        ErrorKind::Malformed,
                        "Unable parse multibase secret material",
                    )
                    .map(KnownKeyPair::X25519)
            }

            (
                SecretType::Ed25519VerificationKey2020,
                SecretMaterial::Multibase(ref multibase_value),
            ) => {
                if !multibase_value.starts_with('z') {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Multibase must start with 'z'",
                    ))?
                }
                let decoded_multibase_value =
                    multibase_value.split_at(1).1.from_base58().map_err(|_e| {
                        err_msg(
                            ErrorKind::IllegalArgument,
                            "Wrong multibase value in secret material",
                        )
                    })?;

                let (codec, decoded_value) = _from_multicodec(&decoded_multibase_value)?;
                if codec != Codec::Ed25519Priv {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong codec in multibase secret material",
                    ))?
                }

                let curve25519_point_size = 32;
                let (d_value, x_value) = decoded_value.split_at(curve25519_point_size);
                let base64_url_d_value = base64::encode_config(&d_value, base64::URL_SAFE_NO_PAD);
                let base64_url_x_value = base64::encode_config(&x_value, base64::URL_SAFE_NO_PAD);

                let jwk = json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64_url_x_value,
                    "d": base64_url_d_value
                });

                Ed25519KeyPair::from_jwk_value(&jwk)
                    .kind(
                        ErrorKind::Malformed,
                        "Unable parse multibase secret material",
                    )
                    .map(KnownKeyPair::Ed25519)
            }

            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported secret method type and material combination",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Codec {
    X25519Pub,
    Ed25519Pub,
    X25519Priv,
    Ed25519Priv,
}

impl Codec {
    fn codec_by_prefix(value: &u32) -> Result<Codec> {
        return match value {
            0xEC => Ok(Codec::X25519Pub),
            0xED => Ok(Codec::Ed25519Pub),
            0x1302 => Ok(Codec::X25519Priv),
            0x1300 => Ok(Codec::Ed25519Priv),
            _ => Err(err_msg(ErrorKind::IllegalArgument, "Unsupported prefix")),
        };
    }
}

fn _from_multicodec(value: &Vec<u8>) -> Result<(Codec, &[u8])> {
    let mut val: Cursor<Vec<u8>> = Cursor::new(value.clone());
    let prefix_int = val.read_unsigned_varint_32().map_err(|_e| {
        err_msg(
            ErrorKind::IllegalArgument,
            "Wrong prefix in verification material",
        )
    })?;
    let codec = Codec::codec_by_prefix(&prefix_int)?;

    let mut prefix: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    prefix.write_unsigned_varint_32(prefix_int).map_err(|_e| {
        err_msg(
            ErrorKind::IllegalArgument,
            "Wrong prefix in verification material",
        )
    })?;

    return Ok((codec, value.split_at(prefix.into_inner().len()).1));
}

#[cfg(test)]
mod tests {
    use crate::did::{VerificationMaterial, VerificationMethod, VerificationMethodType};
    use crate::jwk::FromJwkValue;
    use crate::secrets::{Secret, SecretMaterial, SecretType};
    use crate::utils::crypto::{AsKnownKeyPair, KnownKeyPair};
    use crate::utils::did::{did_or_url, is_did};
    use askar_crypto::alg::ed25519::Ed25519KeyPair;
    use askar_crypto::alg::x25519::X25519KeyPair;
    use serde_json::json;

    #[test]
    fn secret_as_key_pair_x25519_2019_base58_works() {
        let actual_key = Secret {
            id: "did:example:eve#key-x25519-1".to_string(),
            type_: SecretType::X25519KeyAgreementKey2019,
            secret_material: (SecretMaterial::Base58("2b5J8uecvwAo9HUGge5NKQ7HoRNKUKCjZ7Fr4mDgWkwqFyjLPWt7rv5kL3UPeG3e4B9Sy4H2Q2zAuWcP2RNtgJ4t".to_string())),
        }.as_key_pair().unwrap();

        let expected_key = X25519KeyPair::from_jwk_value(&json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "piw5XSMkceDeklaHQZXPBLQySyAwF8eZ-vddihdURS0",
            "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg"
        }))
        .map(KnownKeyPair::X25519)
        .unwrap();
        assert_eq!(format!("{:?}", actual_key), format!("{:?}", expected_key));
    }

    #[test]
    fn secret_as_key_pair_ed25519_2018_base58_works() {
        let actual_key = Secret {
            id: "did:example:eve#key-ed25519-1".to_string(),
            type_: SecretType::Ed25519VerificationKey2018,
            secret_material: (SecretMaterial::Base58("2b5J8uecvwAo9HUGge5NKQ7HoRNKUKCjZ7Fr4mDgWkwqATnLmZDx7Seu6NqTuFKkxuHNT27GcoxVZQCkWJhNvaUQ".to_string())),
        }.as_key_pair().unwrap();

        let expected_key = Ed25519KeyPair::from_jwk_value(&json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
            "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg"
        }))
        .map(KnownKeyPair::Ed25519)
        .unwrap();
        assert_eq!(format!("{:?}", actual_key), format!("{:?}", expected_key));
    }

    #[test]
    fn secret_as_key_pair_x25519_2020_multibase_works() {
        let actual_key = Secret {
            id: "did:example:eve#key-x25519-1".to_string(),
            type_: SecretType::X25519KeyAgreementKey2020,
            secret_material: (SecretMaterial::Multibase("zshCmpUZKtFrAfudMf7NzD3oR6yhWe6i2434FDktk9CYZfkndn7suDrqnRWvrVDHk95Z7vBRJChFxTgBF9qzq7D3xPe".to_string())),
        }.as_key_pair().unwrap();

        let expected_key = X25519KeyPair::from_jwk_value(&json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "piw5XSMkceDeklaHQZXPBLQySyAwF8eZ-vddihdURS0",
            "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg"
        }))
        .map(KnownKeyPair::X25519)
        .unwrap();
        assert_eq!(format!("{:?}", actual_key), format!("{:?}", expected_key));
    }

    #[test]
    fn secret_as_key_pair_ed25519_2020_multibase_works() {
        let actual_key = Secret {
            id: "did:example:eve#key-ed25519-1".to_string(),
            type_: SecretType::Ed25519VerificationKey2020,
            secret_material: (SecretMaterial::Multibase("zrv2DyJwnoQWzS74nPkHHdM7NYH27BRNFBG9To7Fca9YzWhfBVa9Mek52H9bJexjdNqxML1F3TGCpjLNkCwwgQDvd5J".to_string())),
        }.as_key_pair().unwrap();

        let expected_key = Ed25519KeyPair::from_jwk_value(&json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
            "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg"
        }))
        .map(KnownKeyPair::Ed25519)
        .unwrap();
        assert_eq!(format!("{:?}", actual_key), format!("{:?}", expected_key));
    }

    #[test]
    fn verification_method_as_key_pair_x25519_2019_base58_works() {
        let actual_key = VerificationMethod {
            id: "did:example:eve#key-x25519-1".to_string(),
            type_: VerificationMethodType::X25519KeyAgreementKey2019,
            controller: "did:example:eve#key-x25519-1".to_string(),
            verification_material: (VerificationMaterial::Base58(
                "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr".to_string(),
            )),
        }
        .as_key_pair()
        .unwrap();

        let expected_key = X25519KeyPair::from_jwk_value(&json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
        }))
        .map(KnownKeyPair::X25519)
        .unwrap();
        assert_eq!(format!("{:?}", actual_key), format!("{:?}", expected_key));
    }

    #[test]
    fn verification_method_as_key_pair_ed25519_2018_base58_works() {
        let actual_key = VerificationMethod {
            id: "did:example:eve#key-ed25519-1".to_string(),
            type_: VerificationMethodType::Ed25519VerificationKey2018,
            controller: "did:example:eve#key-ed25519-1".to_string(),
            verification_material: (VerificationMaterial::Base58(
                "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7".to_string(),
            )),
        }
        .as_key_pair()
        .unwrap();

        let expected_key = Ed25519KeyPair::from_jwk_value(&json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
        }))
        .map(KnownKeyPair::Ed25519)
        .unwrap();
        assert_eq!(format!("{:?}", actual_key), format!("{:?}", expected_key));
    }

    #[test]
    fn verification_method_as_key_pair_x25519_2020_multibase_works() {
        let actual_key = VerificationMethod {
            id: "did:example:eve#key-x25519-1".to_string(),
            type_: VerificationMethodType::X25519KeyAgreementKey2020,
            controller: "did:example:eve#key-x25519-1".to_string(),
            verification_material: (VerificationMaterial::Multibase(
                "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc".to_string(),
            )),
        }
        .as_key_pair()
        .unwrap();

        let expected_key = X25519KeyPair::from_jwk_value(&json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
        }))
        .map(KnownKeyPair::X25519)
        .unwrap();
        assert_eq!(format!("{:?}", actual_key), format!("{:?}", expected_key));
    }

    #[test]
    fn verification_method_as_key_pair_ed25519_2020_multibase_works() {
        let actual_key = VerificationMethod {
            id: "did:example:eve#key-ed25519-1".to_string(),
            type_: VerificationMethodType::Ed25519VerificationKey2020,
            controller: "did:example:eve#key-ed25519-1".to_string(),
            verification_material: (VerificationMaterial::Multibase(
                "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V".to_string(),
            )),
        }
        .as_key_pair()
        .unwrap();

        let expected_key = Ed25519KeyPair::from_jwk_value(&json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
        }))
        .map(KnownKeyPair::Ed25519)
        .unwrap();
        assert_eq!(format!("{:?}", actual_key), format!("{:?}", expected_key));
    }

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
