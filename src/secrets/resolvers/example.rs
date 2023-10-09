use crate::error::{err_msg, ErrorKind, ResultExt, ToResult};
use crate::jwk::FromJwkValue;
use crate::secrets::{KidOrJwk, KnownSignatureType};
use crate::utils::crypto::{AsKnownKeyPair, JoseKDF, KnownKeyAlg, KnownKeyPair};
use crate::utils::did::{Codec, _from_multicodec};
use crate::{error::Result, secrets::KeyManagementService};
use aries_askar::crypto::{
    alg::{
        aes::{A256Kw, AesKey},
        ed25519::Ed25519KeyPair,
        k256::K256KeyPair,
        p256::P256KeyPair,
        x25519::X25519KeyPair,
        AnyKey, AnyKeyCreate,
    },
    buffer::SecretBytes,
    jwk::FromJwk,
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs},
    repr::{KeyPublicBytes, KeySecretBytes},
    sign::KeySign,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct ExampleKMS {
    known_secrets: Vec<Secret>,
}

impl ExampleKMS {
    pub fn new(known_secrets: Vec<Secret>) -> Self {
        ExampleKMS { known_secrets }
    }

    fn get_secret(&self, secret_id: &str) -> Result<Secret> {
        self.known_secrets
            .iter()
            .find(|s| s.id == secret_id)
            .map(|s| s.clone())
            .ok_or(err_msg(ErrorKind::InvalidState, "Secret not found"))
    }

    fn resolve_key(&self, x: KidOrJwk) -> Result<KnownKeyPair> {
        match x {
            KidOrJwk::Kid(kid) => self.get_secret(&kid)?.as_key_pair(),
            KidOrJwk::X25519Key(jwk) => X25519KeyPair::from_jwk(&jwk)
                .kind(ErrorKind::Malformed, "Unable parse jwk")
                .map(KnownKeyPair::X25519),
            KidOrJwk::P256Key(jwk) => P256KeyPair::from_jwk(&jwk)
                .kind(ErrorKind::Malformed, "Unable parse jwk")
                .map(KnownKeyPair::P256),
        }
    }
}

#[cfg_attr(feature = "uniffi", async_trait)]
#[cfg_attr(not(feature = "uniffi"), async_trait(?Send))]
impl KeyManagementService for ExampleKMS {
    async fn get_key_alg(&self, secret_id: &str) -> Result<KnownKeyAlg> {
        let secret = self.get_secret(secret_id)?;

        match (&secret.type_, &secret.secret_material) {
            (
                SecretType::JsonWebKey2020,
                SecretMaterial::JWK {
                    private_key_jwk: ref value,
                },
            ) => match (value["kty"].as_str(), value["crv"].as_str()) {
                (Some(kty), Some(crv)) if kty == "EC" && crv == "P-256" => Ok(KnownKeyAlg::P256),
                (Some(kty), Some(crv)) if kty == "EC" && crv == "secp256k1" => {
                    Ok(KnownKeyAlg::K256)
                }
                (Some(kty), Some(crv)) if kty == "OKP" && crv == "Ed25519" => {
                    Ok(KnownKeyAlg::Ed25519)
                }
                (Some(kty), Some(crv)) if kty == "OKP" && crv == "X25519" => {
                    Ok(KnownKeyAlg::X25519)
                }
                _ => Err(err_msg(
                    ErrorKind::Unsupported,
                    "Unsupported key type or curve",
                )),
            },
            (
                SecretType::X25519KeyAgreementKey2019,
                SecretMaterial::Base58 {
                    private_key_base58: _,
                },
            ) => Ok(KnownKeyAlg::X25519),
            (
                SecretType::Ed25519VerificationKey2018,
                SecretMaterial::Base58 {
                    private_key_base58: _,
                },
            ) => Ok(KnownKeyAlg::Ed25519),
            (
                SecretType::X25519KeyAgreementKey2020,
                SecretMaterial::Multibase {
                    private_key_multibase: _,
                },
            ) => Ok(KnownKeyAlg::X25519),
            (
                SecretType::Ed25519VerificationKey2020,
                SecretMaterial::Multibase {
                    private_key_multibase: _,
                },
            ) => Ok(KnownKeyAlg::Ed25519),
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported key type or curve",
            )),
        }
    }

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        Ok(secret_ids
            .iter()
            .filter(|&&sid| self.known_secrets.iter().find(|s| s.id == sid).is_some())
            .map(|sid| *sid)
            .collect())
    }

    async fn create_signature(
        &self,
        secret_id: &str,
        message: &[u8],
        sig_type: Option<KnownSignatureType>,
    ) -> Result<SecretBytes> {
        let secret = self.get_secret(secret_id)?;

        match secret.as_key_pair()? {
            KnownKeyPair::X25519(_) => {
                Err(err_msg(ErrorKind::Unsupported, "Unsupported signature alg"))
            }
            KnownKeyPair::Ed25519(key) => key
                .create_signature(message, sig_type.map(|x| x.into()))
                .kind(ErrorKind::InvalidState, "Unable create signature"),
            KnownKeyPair::P256(key) => key
                .create_signature(message, sig_type.map(|x| x.into()))
                .kind(ErrorKind::InvalidState, "Unable create signature"),
            KnownKeyPair::K256(key) => key
                .create_signature(message, sig_type.map(|x| x.into()))
                .kind(ErrorKind::InvalidState, "Unable create signature"),
        }
    }

    async fn derive_aes_key_using_ecdh_1pu(
        &self,
        ephem_key: KidOrJwk, // epk + sk + rk -> cek
        send_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let ephem_key = self.resolve_key(ephem_key)?;
        let send_key = self.resolve_key(send_key)?;
        let recip_key = self.resolve_key(recip_key)?;

        match (ephem_key, send_key, recip_key) {
            (
                KnownKeyPair::X25519(ephem_key),
                KnownKeyPair::X25519(send_key),
                KnownKeyPair::X25519(recip_key),
            ) => Ecdh1PU::derive_key(
                &ephem_key,
                Some(&send_key),
                &recip_key,
                &alg,
                &apu,
                &apv,
                &cc_tag,
                receive,
            ),
            (
                KnownKeyPair::P256(ephem_key),
                KnownKeyPair::P256(send_key),
                KnownKeyPair::P256(recip_key),
            ) => Ecdh1PU::derive_key(
                &ephem_key,
                Some(&send_key),
                &recip_key,
                &alg,
                &apu,
                &apv,
                &cc_tag,
                receive,
            ),
            _ => Err(err_msg(ErrorKind::Unsupported, "Unsupported derive keys")),
        }
    }

    async fn derive_aes_key_using_ecdh_es(
        &self,
        ephem_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let ephem_key = self.resolve_key(ephem_key)?;
        let recip_key = self.resolve_key(recip_key)?;

        match (ephem_key, recip_key) {
            (KnownKeyPair::X25519(ephem_key), KnownKeyPair::X25519(recip_key)) => {
                EcdhEs::derive_key(&ephem_key, None, &recip_key, &alg, &apu, &apv, &[], receive)
            }
            (KnownKeyPair::P256(ephem_key), KnownKeyPair::P256(recip_key)) => {
                EcdhEs::derive_key(&ephem_key, None, &recip_key, &alg, &apu, &apv, &[], receive)
            }
            _ => Err(err_msg(ErrorKind::Unsupported, "Unsupported derive keys")),
        }
    }
}

/// Represents secret.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Secret {
    /// A key ID identifying a secret (private key).
    pub id: String,

    /// Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
    #[serde(rename = "type")]
    pub type_: SecretType,

    /// Value of the secret (private key)
    #[serde(flatten)]
    pub secret_material: SecretMaterial,
}

/// Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum SecretType {
    JsonWebKey2020,
    X25519KeyAgreementKey2019,
    X25519KeyAgreementKey2020,
    Ed25519VerificationKey2018,
    Ed25519VerificationKey2020,
    EcdsaSecp256k1VerificationKey2019,
    Other,
}

/// Represents secret crypto material.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SecretMaterial {
    #[serde(rename_all = "camelCase")]
    JWK { private_key_jwk: Value },

    #[serde(rename_all = "camelCase")]
    Multibase { private_key_multibase: String },

    #[serde(rename_all = "camelCase")]
    Base58 { private_key_base58: String },
}

impl Secret {
    pub fn to_key(&self) -> Result<Arc<AnyKey>> {
        // Box::new(KeyT(self.as_key_pair().unwrap()))
        let any_key = match self.as_key_pair()? {
            KnownKeyPair::Ed25519(key) => Arc::<AnyKey>::from_key(key),
            KnownKeyPair::X25519(key) => Arc::<AnyKey>::from_key(key),
            KnownKeyPair::P256(key) => Arc::<AnyKey>::from_key(key),
            KnownKeyPair::K256(key) => Arc::<AnyKey>::from_key(key),
        };
        Ok(any_key)
    }
}

impl AsKnownKeyPair for Secret {
    fn key_alg(&self) -> KnownKeyAlg {
        match (&self.type_, &self.secret_material) {
            (
                SecretType::JsonWebKey2020,
                SecretMaterial::JWK {
                    private_key_jwk: ref value,
                },
            ) => match (value["kty"].as_str(), value["crv"].as_str()) {
                (Some(kty), Some(crv)) if kty == "EC" && crv == "P-256" => KnownKeyAlg::P256,
                (Some(kty), Some(crv)) if kty == "EC" && crv == "secp256k1" => KnownKeyAlg::K256,
                (Some(kty), Some(crv)) if kty == "OKP" && crv == "Ed25519" => KnownKeyAlg::Ed25519,
                (Some(kty), Some(crv)) if kty == "OKP" && crv == "X25519" => KnownKeyAlg::X25519,
                _ => KnownKeyAlg::Unsupported,
            },
            (
                SecretType::X25519KeyAgreementKey2019,
                SecretMaterial::Base58 {
                    private_key_base58: _,
                },
            ) => KnownKeyAlg::X25519,
            (
                SecretType::Ed25519VerificationKey2018,
                SecretMaterial::Base58 {
                    private_key_base58: _,
                },
            ) => KnownKeyAlg::Ed25519,
            (
                SecretType::X25519KeyAgreementKey2020,
                SecretMaterial::Multibase {
                    private_key_multibase: _,
                },
            ) => KnownKeyAlg::X25519,
            (
                SecretType::Ed25519VerificationKey2020,
                SecretMaterial::Multibase {
                    private_key_multibase: _,
                },
            ) => KnownKeyAlg::Ed25519,
            _ => KnownKeyAlg::Unsupported,
        }
    }

    fn as_key_pair(&self) -> Result<KnownKeyPair> {
        match (&self.type_, &self.secret_material) {
            (
                SecretType::JsonWebKey2020,
                SecretMaterial::JWK {
                    private_key_jwk: ref value,
                },
            ) => match (value["kty"].as_str(), value["crv"].as_str()) {
                (Some(kty), Some(crv)) if kty == "EC" && crv == "P-256" => {
                    P256KeyPair::from_jwk_value(value)
                        .kind(ErrorKind::Malformed, "Unable parse jwk")
                        .map(KnownKeyPair::P256)
                }
                (Some(kty), Some(crv)) if kty == "EC" && crv == "secp256k1" => {
                    K256KeyPair::from_jwk_value(value)
                        .kind(ErrorKind::Malformed, "Unable parse jwk")
                        .map(KnownKeyPair::K256)
                }
                (Some(kty), Some(crv)) if kty == "OKP" && crv == "Ed25519" => {
                    Ed25519KeyPair::from_jwk_value(value)
                        .kind(ErrorKind::Malformed, "Unable parse jwk")
                        .map(KnownKeyPair::Ed25519)
                }
                (Some(kty), Some(crv)) if kty == "OKP" && crv == "X25519" => {
                    X25519KeyPair::from_jwk_value(value)
                        .kind(ErrorKind::Malformed, "Unable parse jwk")
                        .map(KnownKeyPair::X25519)
                }
                _ => Err(err_msg(
                    ErrorKind::Unsupported,
                    "Unsupported key type or curve",
                )),
            },

            (
                SecretType::X25519KeyAgreementKey2019,
                SecretMaterial::Base58 {
                    private_key_base58: ref value,
                },
            ) => {
                let decoded_value = bs58::decode(value)
                    .into_vec()
                    .to_didcomm("Wrong base58 value in secret material")?;

                let key_pair = X25519KeyPair::from_secret_bytes(&decoded_value)
                    .kind(ErrorKind::Malformed, "Unable parse x25519 secret material")?;

                let mut jwk = json!({
                    "kty": "OKP",
                    "crv": "X25519",
                });

                key_pair.with_public_bytes(|buf| {
                    jwk["x"] = Value::String(base64::encode_config(buf, base64::URL_SAFE_NO_PAD))
                });

                key_pair.with_secret_bytes(|buf| {
                    if let Some(sk) = buf {
                        jwk["d"] = Value::String(base64::encode_config(sk, base64::URL_SAFE_NO_PAD))
                    }
                });

                X25519KeyPair::from_jwk_value(&jwk)
                    .kind(ErrorKind::Malformed, "Unable parse base58 secret material")
                    .map(KnownKeyPair::X25519)
            }

            (
                SecretType::Ed25519VerificationKey2018,
                SecretMaterial::Base58 {
                    private_key_base58: ref value,
                },
            ) => {
                let decoded_value = bs58::decode(value)
                    .into_vec()
                    .to_didcomm("Wrong base58 value in secret material")?;

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
                SecretMaterial::Multibase {
                    private_key_multibase: ref value,
                },
            ) => {
                if !value.starts_with('z') {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Multibase must start with 'z'",
                    ))?
                }
                let decoded_multibase_value = bs58::decode(&value[1..])
                    .into_vec()
                    .to_didcomm("Wrong multibase value in secret material")?;

                let (codec, decoded_value) = _from_multicodec(&decoded_multibase_value)?;
                if codec != Codec::X25519Priv {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong codec in multibase secret material",
                    ))?
                }

                let key_pair = X25519KeyPair::from_secret_bytes(&decoded_value)
                    .kind(ErrorKind::Malformed, "Unable parse x25519 secret material")?;

                let mut jwk = json!({
                    "kty": "OKP",
                    "crv": "X25519",
                });

                key_pair.with_public_bytes(|buf| {
                    jwk["x"] = Value::String(base64::encode_config(buf, base64::URL_SAFE_NO_PAD))
                });

                key_pair.with_secret_bytes(|buf| {
                    if let Some(sk) = buf {
                        jwk["d"] = Value::String(base64::encode_config(sk, base64::URL_SAFE_NO_PAD))
                    }
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
                SecretMaterial::Multibase {
                    private_key_multibase: ref value,
                },
            ) => {
                if !value.starts_with('z') {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Multibase must start with 'z'",
                    ))?
                }
                let decoded_multibase_value = bs58::decode(&value[1..])
                    .into_vec()
                    .to_didcomm("Wrong multibase value in secret material")?;

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
