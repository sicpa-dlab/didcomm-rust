//! DID Resolver (https://www.w3.org/TR/did-core/#dfn-did-resolvers) interfaces

use async_trait::async_trait;

use crate::{did::did_doc::DIDDoc, error::Result};

/// Represents DID Doc resolver (https://www.w3.org/TR/did-core/#did-resolution).
#[cfg(feature = "uniffi")]
#[async_trait]
pub trait DIDResolver: Sync {
    /// Resolves a DID document by the given DID.
    ///
    /// # Params
    /// - `did` a DID to be resolved.
    ///
    /// # Returns
    /// An instance of resolved DID DOC or None if DID is not found.
    ///
    /// # Errors
    /// - `IoError` IO error during resolving
    /// - `InvalidState` indicates a bug in resolver code
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>>;
}

/// Represents DID Doc resolver (https://www.w3.org/TR/did-core/#did-resolution).
#[cfg(not(feature = "uniffi"))]
#[async_trait(?Send)]
pub trait DIDResolver {
    /// Resolves a DID document by the given DID.
    ///
    /// # Params
    /// - `did` a DID to be resolved.
    ///
    /// # Returns
    /// An instance of resolved DID DOC or None if DID is not found.
    ///
    /// # Errors
    /// - `IoError` IO error during resolving
    /// - `InvalidState` indicates a bug in resolver code
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>>;
}
