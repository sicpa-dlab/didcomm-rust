use crate::error::{err_msg, ErrorKind, ResultExt};
use crate::secrets::{SecretMaterial, SecretType};
use crate::utils::crypto::{AsKnownKeyPair, JoseKDF, KnownKeyPair};
use crate::{
    error::Result,
    secrets::{Secret, SecretsResolver},
};
use askar_crypto::alg::aes::{A256Kw, AesKey};
use askar_crypto::alg::p256::P256KeyPair;
use askar_crypto::alg::x25519::X25519KeyPair;
use askar_crypto::alg::{EcCurves, KeyAlg};
use askar_crypto::buffer::SecretBytes;
use askar_crypto::kdf::ecdh_1pu::Ecdh1PU;
use askar_crypto::kdf::ecdh_es::EcdhEs;
use askar_crypto::sign::{KeySign, SignatureType};
use async_trait::async_trait;

pub struct ExampleSecretsResolver {
    known_secrets: Vec<Secret>,
}

impl ExampleSecretsResolver {
    pub fn new(known_secrets: Vec<Secret>) -> Self {
        ExampleSecretsResolver { known_secrets }
    }

    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        Ok(self
            .known_secrets
            .iter()
            .find(|s| s.id == secret_id)
            .map(|s| s.clone()))
    }
}

#[cfg_attr(feature = "uniffi", async_trait)]
#[cfg_attr(not(feature = "uniffi"), async_trait(?Send))]
impl SecretsResolver for ExampleSecretsResolver {
    async fn get_key_alg(&self, secret_id: &str) -> Result<KeyAlg> {
        let secret = self
            .known_secrets
            .iter()
            .find(|s| s.id == secret_id)
            .cloned()
            .ok_or(err_msg(ErrorKind::InvalidState, "Secret not found"))?;

        match (&secret.type_, &secret.secret_material) {
            (
                SecretType::JsonWebKey2020,
                SecretMaterial::JWK {
                    private_key_jwk: ref value,
                },
            ) => match (value["kty"].as_str(), value["crv"].as_str()) {
                (Some(kty), Some(crv)) if kty == "EC" && crv == "P-256" => {
                    Ok(KeyAlg::EcCurve(EcCurves::Secp256r1))
                }
                (Some(kty), Some(crv)) if kty == "EC" && crv == "secp256k1" => {
                    Ok(KeyAlg::EcCurve(EcCurves::Secp256k1))
                }
                (Some(kty), Some(crv)) if kty == "OKP" && crv == "Ed25519" => Ok(KeyAlg::Ed25519),
                (Some(kty), Some(crv)) if kty == "OKP" && crv == "X25519" => Ok(KeyAlg::X25519),
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
            ) => Ok(KeyAlg::X25519),
            (
                SecretType::Ed25519VerificationKey2018,
                SecretMaterial::Base58 {
                    private_key_base58: _,
                },
            ) => Ok(KeyAlg::Ed25519),
            (
                SecretType::X25519KeyAgreementKey2020,
                SecretMaterial::Multibase {
                    private_key_multibase: _,
                },
            ) => Ok(KeyAlg::X25519),
            (
                SecretType::Ed25519VerificationKey2020,
                SecretMaterial::Multibase {
                    private_key_multibase: _,
                },
            ) => Ok(KeyAlg::Ed25519),
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
        sig_type: Option<SignatureType>,
    ) -> Result<SecretBytes> {
        let secret = self
            .known_secrets
            .iter()
            .find(|s| s.id == secret_id)
            .cloned()
            .expect("Secret not found");
        match secret.as_key_pair()? {
            KnownKeyPair::X25519(ref key) => {
                Err(err_msg(ErrorKind::Unsupported, "Unsupported signature alg"))
            }
            KnownKeyPair::Ed25519(key) => key
                .create_signature(message, sig_type)
                .kind(ErrorKind::InvalidState, "Unable create signature"),
            KnownKeyPair::P256(key) => key
                .create_signature(message, sig_type)
                .kind(ErrorKind::InvalidState, "Unable create signature"),
            KnownKeyPair::K256(key) => key
                .create_signature(message, sig_type)
                .kind(ErrorKind::InvalidState, "Unable create signature"),
        }
    }

    async fn derive_aes_key_from_x25519_using_edch1pu(
        &self,
        ephem_key: X25519KeyPair,
        send_kid: String,
        recip_key: X25519KeyPair,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(&send_kid).await?.expect("Secret not found");

        Ecdh1PU::derive_key(
            &ephem_key,
            Some(&key.as_x25519()?),
            &recip_key,
            &alg,
            &apu,
            &apv,
            &cc_tag,
            receive,
        )
    }

    async fn derive_aes_key_from_p256_using_edch1pu(
        &self,
        ephem_key: P256KeyPair,
        send_kid: String,
        recip_key: P256KeyPair,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(&send_kid).await?.expect("Secret not found");

        Ecdh1PU::derive_key(
            &ephem_key,
            Some(&key.as_p256()?),
            &recip_key,
            &alg,
            &apu,
            &apv,
            &cc_tag,
            receive,
        )
    }

    async fn derive_aes_key_from_x25519_using_edch1pu_receive(
        &self,
        ephem_key: X25519KeyPair,
        send_key: X25519KeyPair,
        recip_kid: &str,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(recip_kid).await?.expect("Secret not found");

        Ecdh1PU::derive_key(
            &ephem_key,
            Some(&send_key),
            &key.as_x25519()?,
            &alg,
            &apu,
            &apv,
            &cc_tag,
            receive,
        )
    }

    async fn derive_aes_key_from_p256_using_edch1pu_receive(
        &self,
        ephem_key: P256KeyPair,
        send_key: P256KeyPair,
        recip_kid: &str,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(recip_kid).await?.expect("Secret not found");

        Ecdh1PU::derive_key(
            &ephem_key,
            Some(&send_key),
            &key.as_p256()?,
            &alg,
            &apu,
            &apv,
            &cc_tag,
            receive,
        )
    }

    async fn derive_aes_key_from_x25519_using_edches(
        &self,
        ephem_key: X25519KeyPair,
        recip_kid: &str,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(recip_kid).await?.expect("Secret not found");

        EcdhEs::derive_key(
            &ephem_key,
            None,
            &key.as_x25519()?,
            &alg,
            &apu,
            &apv,
            &[],
            receive,
        )
    }

    async fn derive_aes_key_from_p256_using_edches(
        &self,
        ephem_key: P256KeyPair,
        recip_kid: &str,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(recip_kid).await?.expect("Secret not found");

        EcdhEs::derive_key(
            &ephem_key,
            None,
            &key.as_p256()?,
            &alg,
            &apu,
            &apv,
            &[],
            receive,
        )
    }
}
