use async_trait::async_trait;

use crate::{
    did::{DIDDoc, DIDResolver},
    error::Result,
};

/// Allows resolve pre-defined did's for `example` and other methods.
pub struct ExampleDIDResolver {}

impl ExampleDIDResolver {
    pub fn new() -> Self {
        ExampleDIDResolver {}
    }
}

#[async_trait]
impl DIDResolver for ExampleDIDResolver {
    async fn resolve(&self, _did: &str) -> Result<Box<dyn DIDDoc>> {
        todo!()
    }
}
