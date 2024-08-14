use std::sync::Arc;

use didcomm_core::secrets::{KidOrJwk, KnownKeyAlg, KnownSignatureType};

use crate::common::{ErrorCode, OnResult};

pub enum KidOrJwkAdapted {
    Kid { kid: String },
    Jwk { jwk: String },
}

impl From<KidOrJwk> for KidOrJwkAdapted {
    fn from(x: KidOrJwk) -> Self {
        match x {
            KidOrJwk::Kid(kid) => Self::Kid { kid },
            KidOrJwk::P256Key(jwk) => Self::Jwk { jwk },
            KidOrJwk::X25519Key(jwk) => Self::Jwk { jwk },
        }
    }
}

/// Interface for secrets resolver.
/// Resolves secrets such as private keys to be used for signing and encryption.
pub trait KeyManagementService: Sync + Send {
    /// Finds secret (usually private key) identified by the given key ID.
    ///
    /// # Parameters
    /// - `secret_id` the ID (in form of DID URL) identifying a secret
    /// - `cb` a callback with a result
    ///
    /// # Returns
    /// A secret (usually private key) or None of there is no secret for the given ID
    ///
    // fn get_secret(&self, secret_id: String, cb: Arc<OnGetSecretResult>) -> ErrorCode;

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
    fn get_key_alg(&self, secret_id: String, cb: Arc<OnGetKeyAlgResult>) -> ErrorCode;

    /// Find all secrets that have one of the given IDs.
    /// Return secrets only for key IDs for which a secret is present.
    ///
    /// # Parameters
    /// - `secret_ids` the IDs find secrets for
    /// - `cb` a callback with a result
    ///
    /// # Returns
    /// A secret (usually private key) or None of there is no secret for the given ID
    ///
    fn find_secrets(&self, secret_ids: Vec<String>, cb: Arc<OnFindSecretsResult>) -> ErrorCode;

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
    fn create_signature(
        &self,
        secret_id: String,
        message: Vec<u8>,
        sig_type: Option<KnownSignatureType>,
        cb: Arc<OnSecretBytesResult>,
    ) -> ErrorCode;

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
    fn derive_aes_key_using_ecdh_1pu(
        &self,
        ephem_key: KidOrJwkAdapted,
        send_key: KidOrJwkAdapted,
        recip_key: KidOrJwkAdapted,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
        cb: Arc<OnSecretBytesResult>,
    ) -> ErrorCode;

    /// ECDH-ES derivation of key
    ///
    /// # Parameters
    /// - `ephem_key` Ephemeral key (cannot be kid)
    /// - `recip_key`: Recipient key (or kid to be resolved by KMS)
    /// - `alg`: algorithm
    /// - `apu`: Sender info
    /// - `apv`: Receiver info
    /// - `receive`: Whether derived key is used on receive or send side.
    fn derive_aes_key_using_ecdh_es(
        &self,
        ephem_key: KidOrJwkAdapted,
        recip_key: KidOrJwkAdapted,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
        cb: Arc<OnSecretBytesResult>,
    ) -> ErrorCode;
}

pub type OnGetKeyAlgResult = OnResult<KnownKeyAlg>;
pub type OnFindSecretsResult = OnResult<Vec<String>>;
pub type OnSecretBytesResult = OnResult<Vec<u8>>;
