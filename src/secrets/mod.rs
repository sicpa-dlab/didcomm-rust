//! Set of interfaces that allow access to DID Document secrets

pub mod resolvers;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;

/// Interface for secrets resolver.
#[async_trait]
pub trait SecretsResolver {
    async fn resolve(&self, did_url: &str) -> Result<Secret>;
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
