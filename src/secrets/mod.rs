//! Set of interfaces that allow access to DID Document secrets

pub mod resolvers;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;

/// Interface for secrets resolver.
/// Resolves secrets such as private keys to be used for signing and encryption.
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
pub enum SecretMaterial {
    JWK {
        #[serde(flatten)]
        value: Value,
    },
    Multibase {
        #[serde(flatten)]
        value: String,
    },
    Base58 {
        #[serde(flatten)]
        value: String,
    },
    Hex {
        #[serde(flatten)]
        value: String,
    },
    Other {
        #[serde(flatten)]
        value: Value,
    },
}
