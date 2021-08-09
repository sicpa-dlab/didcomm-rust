//! DID Resolver (https://www.w3.org/TR/did-core/#dfn-did-resolvers) interfaces

use async_trait::async_trait;

use crate::{did::did_doc::DIDDoc, error::Result};

/// Represents DID Doc resolver (https://www.w3.org/TR/did-core/#did-resolution).
#[async_trait]
pub trait DIDResolver {
    async fn resolve(&self, did: &str) -> Result<Box<dyn DIDDoc>>;
}
