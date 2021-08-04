//! DID Resolver (https://www.w3.org/TR/did-core/#dfn-did-resolvers) interfaces

use crate::did::did_doc::DIDDoc;
use crate::error::Result;

/**
 * Interface for DID Documents (https://www.w3.org/TR/did-core/#did-resolution) resolving.
 */
pub trait DIDResolver {
    fn resolve(did: &str) -> Result<Box<dyn DIDDoc>>;
}
