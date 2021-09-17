//! Set of interfaces that allow access to DID Document secrets

pub mod resolvers;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;

/// Interface for secrets resolver.
/// Resolves secrets such as private keys to be used for signing and encryption.
#[async_trait]
pub trait SecretsResolver {
    /// Finds private key identified by the given key ID.
    ///
    /// # Parameters
    /// - `did_url` the key ID (in form of DID URL) identifying a private key
    ///
    /// # Returns
    /// A private key or None of there is no key for the given key ID
    ///
    /// # Errors
    /// - IOError
    /// - InvalidState
    ///
    async fn resolve(&self, did_url: &str) -> Result<Option<Secret>>;
}

/// Represents secret.
#[derive(Clone, Debug)]
pub struct Secret {
    /// A key ID identifying a secret (private key).
    pub id: String,

    /// Must have the same value, as type ('type' field) of the corresponding method in DID Doc containing a public key.
    pub type_: String,

    /// Value of the secret (private key)
    pub private_key: PrivateKey,
}

/// Represents secret crypto material.
#[derive(Clone, Debug)]
pub enum PrivateKey {
    JWK(Value),
    Multibase(String),
    Hex(String),
    Base58(String),
}
