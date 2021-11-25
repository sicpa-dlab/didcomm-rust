use std::sync::Arc;

use async_trait::async_trait;
use didcomm::did::DIDDoc;

use crate::{common::ErrorCode, did::FFIDIDResolver, OnDIDResolverResult};

/// Allows resolve pre-defined did's for `example` and other methods.
pub struct ExampleFFIDIDResolver {
    known_dids: Vec<DIDDoc>,
}

impl ExampleFFIDIDResolver {
    pub fn new(known_dids: Vec<String>) -> Self {
        ExampleFFIDIDResolver {
            known_dids: known_dids
                .iter()
                .map(|ddoc| serde_json::from_str(ddoc).unwrap())
                .collect(),
        }
    }
}

#[async_trait]
impl FFIDIDResolver for ExampleFFIDIDResolver {
    fn resolve(&self, did: String, cb: Arc<OnDIDResolverResult>) -> ErrorCode {
        let diddoc = self
            .known_dids
            .iter()
            .find(|ddoc| ddoc.did == did)
            .map(|ddoc| ddoc.clone());

        match cb.success(diddoc) {
            Ok(_) => ErrorCode::Success,
            Err(_) => ErrorCode::Error,
        }
    }
}