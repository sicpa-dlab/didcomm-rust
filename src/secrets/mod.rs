//! Set of interfaces that allow access to DID Document secrets

use serde_json::Value;

use crate::error::Result;

/// Interface for secrets resolver.
pub trait SecretsResolver {
    fn resolve(did_url: &str) -> Result<Secret>;
}

/// Represents secret.
pub struct Secret {
    pub id: String,
    pub type_: String,
    pub private_key: PrivateKey,
}

/// Represents secret crypto material.
pub enum PrivateKey {
    JWK(Value),
    Multibase(String),
}
