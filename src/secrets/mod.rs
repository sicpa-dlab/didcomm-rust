//! Set of interfaces that allow access to DID Document secrets

pub mod resolvers;

use askar_crypto::alg::aes::{A256Kw, AesKey};
use askar_crypto::alg::p256::P256KeyPair;
use askar_crypto::alg::x25519::X25519KeyPair;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;

/// Interface for secrets resolver.
/// Resolves secrets such as private keys to be used for signing and encryption.
#[cfg(feature = "uniffi")]
#[async_trait]
pub trait SecretsResolver: Sync {
    /// Finds secret (usually private key) identified by the given key ID.
    ///
    /// # Parameters
    /// - `secret_id` the ID (in form of DID URL) identifying a secret
    ///
    /// # Returns
    /// A secret (usually private key) or None of there is no secret for the given ID
    ///
    /// # Errors
    /// - IOError
    /// - InvalidState
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>>;

    /// Find all secrets that have one of the given IDs.
    /// Return secrets only for key IDs for which a secret is present.
    ///
    /// # Parameters
    /// - `secret_ids` the IDs find secrets for
    ///
    /// # Returns
    /// possible empty list of all secrets that have one of the given IDs.
    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>>;

    async fn derive_aes_key_from_x25519_using_edch1pu(
        &self,
        ephem_key: &X25519KeyPair,
        send_kid: &str,
        recip_key: &X25519KeyPair,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    async fn derive_aes_key_from_p256_using_edch1pu(
        &self,
        ephem_key: &P256KeyPair,
        send_kid: &str,
        recip_key: &P256KeyPair,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    async fn derive_aes_key_from_x25519_using_edch1pu_receive(
        &self,
        ephem_key: &X25519KeyPair,
        send_key: &X25519KeyPair,
        recip_kid: &str,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    async fn derive_aes_key_from_p256_using_edch1pu_receive(
        &self,
        ephem_key: &P256KeyPair,
        send_key: &P256KeyPair,
        recip_kid: &str,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    async fn derive_aes_key_from_x25519_using_edches(
        &self,
        ephem_key: &X25519KeyPair,
        recip_kid: &str,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    async fn derive_aes_key_from_p256_using_edches(
        &self,
        ephem_key: &P256KeyPair,
        recip_kid: &str,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;
}

/// Interface for secrets resolver.
/// Resolves secrets such as private keys to be used for signing and encryption.
#[cfg(not(feature = "uniffi"))]
#[async_trait(?Send)]
pub trait SecretsResolver {
    /// Finds secret (usually private key) identified by the given key ID.
    ///
    /// # Parameters
    /// - `secret_id` the ID (in form of DID URL) identifying a secret
    ///
    /// # Returns
    /// A secret (usually private key) or None of there is no secret for the given ID
    ///
    /// # Errors
    /// - IOError
    /// - InvalidState
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>>;

    /// Find all secrets that have one of the given IDs.
    /// Return secrets only for key IDs for which a secret is present.
    ///
    /// # Parameters
    /// - `secret_ids` the IDs find secrets for
    ///
    /// # Returns
    /// possible empty list of all secrets that have one of the given IDs.
    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>>;

    async fn derive_aes_key_from_x25519_using_edch1pu(
        &self,
        ephem_key: &X25519KeyPair,
        send_kid: &str,
        recip_key: &X25519KeyPair,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    async fn derive_aes_key_from_p256_using_edch1pu(
        &self,
        ephem_key: &P256KeyPair,
        send_kid: &str,
        recip_key: &P256KeyPair,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    async fn derive_aes_key_from_x25519_using_edch1pu_receive(
        &self,
        ephem_key: &X25519KeyPair,
        send_key: &X25519KeyPair,
        recip_kid: &str,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    async fn derive_aes_key_from_p256_using_edch1pu_receive(
        &self,
        ephem_key: &P256KeyPair,
        send_key: &P256KeyPair,
        recip_kid: &str,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    async fn derive_aes_key_from_x25519_using_edches(
        &self,
        ephem_key: &X25519KeyPair,
        recip_kid: &str,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    async fn derive_aes_key_from_p256_using_edches(
        &self,
        ephem_key: &P256KeyPair,
        recip_kid: &str,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;
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
