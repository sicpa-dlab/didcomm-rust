use async_trait::async_trait;

use crate::did::{DIDDoc, DIDResolver};
use crate::error::Result;

/// Allows resolve pre-defined did's for `example` and other methods.
struct ExampleDIDResolver {}

#[async_trait]
impl DIDResolver for ExampleDIDResolver {
    async fn resolve(_did: &str) -> Result<Box<dyn DIDDoc>> {
        todo!()
    }
}
