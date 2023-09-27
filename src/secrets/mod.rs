//! Set of interfaces that allow access to DID Document secrets

pub mod resolvers;

pub use askar_crypto::alg::aes::{A256Kw, AesKey};
pub use askar_crypto::alg::KeyAlg;
pub use askar_crypto::buffer::SecretBytes;
pub use askar_crypto::repr::KeySecretBytes;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;
pub use crate::utils::crypto::KnownKeyAlg;
pub use crate::utils::crypto::KnownSignatureType;

#[derive(Serialize, Deserialize)]
pub enum KidOrJwk {
    Kid(String),
    X25519Key(String),
    P256Key(String),
}

/// Interface for KeyManagementService.
/// Resolves secrets such as private keys to be used for signing and encryption.
#[cfg(feature = "uniffi")]
#[async_trait]
pub trait KeyManagementService: Sync {
    /// Finds secret (usually private key) identified by the given key ID.
    ///
    /// # Parameters
    /// - `secret_id` the ID (in form of DID URL) identifying a secret
    ///
    /// # Returns
    /// A key algorithm of the secret or None of there is no secret for the given ID
    ///
    /// # Errors
    /// - IOError
    /// - InvalidState
    async fn get_key_alg(&self, secret_id: &str) -> Result<KnownKeyAlg>;

    /// Find all secrets that have one of the given IDs.
    /// Return ids of secrets only for key IDs for which a secret is present.
    ///
    /// # Parameters
    /// - `secret_ids` the IDs to check for existence
    ///
    /// # Returns
    /// possible empty list of all secrets IDs that have one of the given IDs.
    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>>;

    /// Create a signature of the requested type and return an allocated
    /// buffer.
    ///
    /// # Parameters
    /// - `secret_id` the ID (in form of DID URL) identifying a secret
    /// - `message` bytes to be signed
    /// - `sig_type`: signature type to be used.
    ///
    /// # Returns
    /// Signature
    ///
    /// # Errors
    /// - IOError
    /// - IvalidState
    /// - Unsupported
    async fn create_signature(
        &self,
        secret_id: &str,
        message: &[u8],
        sig_type: Option<KnownSignatureType>,
    ) -> Result<SecretBytes>;

    /// ECDH-1PU derivation of key
    ///
    /// # Parameters
    /// - `ephem_key` Ephemeral key (cannot be kid)
    /// - `send_key` Sender key (or kid to be resolved by KMS)
    /// - `recip_key`: Recipient key (or kid to be resolved by KMS)
    /// - `alg`: algorithm
    /// - `apu`: Sender info
    /// - `apv`: Receiver info
    /// - `cc_tag`: tag
    /// - `receive`: Whether derived key is used on receive or send side.
    async fn derive_aes_key_using_ecdh_1pu(
        &self,
        ephem_key: KidOrJwk,
        send_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    /// ECDH-ES derivation of key
    ///
    /// # Parameters
    /// - `ephem_key` Ephemeral key (cannot be kid)
    /// - `recip_key`: Recipient key (or kid to be resolved by KMS)
    /// - `alg`: algorithm
    /// - `apu`: Sender info
    /// - `apv`: Receiver info
    /// - `receive`: Whether derived key is used on receive or send side.
    async fn derive_aes_key_using_ecdh_es(
        &self,
        ephem_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;
}

/// Interface for secrets resolver.
/// Resolves secrets such as private keys to be used for signing and encryption.
#[cfg(not(feature = "uniffi"))]
#[async_trait(?Send)]
pub trait KeyManagementService {
    /// Finds secret (usually private key) identified by the given key ID.
    ///
    /// # Parameters
    /// - `secret_id` the ID (in form of DID URL) identifying a secret
    ///
    /// # Returns
    /// A key algorithm of the secret or None of there is no secret for the given ID
    ///
    /// # Errors
    /// - IOError
    /// - InvalidState
    async fn get_key_alg(&self, secret_id: &str) -> Result<KnownKeyAlg>;

    /// Find all secrets that have one of the given IDs.
    /// Return ids of secrets only for key IDs for which a secret is present.
    ///
    /// # Parameters
    /// - `secret_ids` the IDs to check for existence
    ///
    /// # Returns
    /// possible empty list of all secrets IDs that have one of the given IDs.
    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>>;

    /// Create a signature of the requested type and return an allocated
    /// buffer.
    ///
    /// # Parameters
    /// - `secret_id` the ID (in form of DID URL) identifying a secret
    /// - `message` bytes to be signed
    /// - `sig_type`: signature type to be used.
    ///
    /// # Returns
    /// Signature
    ///
    /// # Errors
    /// - IOError
    /// - IvalidState
    /// - Unsupported
    async fn create_signature(
        &self,
        secret_id: &str,
        message: &[u8],
        sig_type: Option<KnownSignatureType>,
    ) -> Result<SecretBytes>;

    /// ECDH-1PU derivation of key
    ///
    /// # Parameters
    /// - `ephem_key` Ephemeral key (cannot be kid)
    /// - `send_key` Sender key (or kid to be resolved by KMS)
    /// - `recip_key`: Recipient key (or kid to be resolved by KMS)
    /// - `alg`: algorithm
    /// - `apu`: Sender info
    /// - `apv`: Receiver info
    /// - `cc_tag`: tag
    /// - `receive`: Whether derived key is used on receive or send side.
    async fn derive_aes_key_using_ecdh_1pu(
        &self,
        ephem_key: KidOrJwk,
        send_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;

    /// ECDH-1PU derivation of key
    ///
    /// # Parameters
    /// - `ephem_key` Ephemeral key (cannot be kid)
    /// - `recip_key`: Recipient key (or kid to be resolved by KMS)
    /// - `alg`: algorithm
    /// - `apu`: Sender info
    /// - `apv`: Receiver info
    /// - `receive`: Whether derived key is used on receive or send side.
    async fn derive_aes_key_using_ecdh_es(
        &self,
        ephem_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>>;
}
