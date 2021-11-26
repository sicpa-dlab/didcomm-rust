use std::sync::Arc;

use didcomm_core::{
    did::{DIDDoc, DIDResolver as _DIDResolver},
    error::{ErrorKind, Result, ResultExt},
};

use async_trait::async_trait;

use crate::{DIDResolver, OnDIDResolverResult};

pub(crate) struct DIDResolverAdapter {
    did_resolver: Arc<Box<dyn DIDResolver>>,
}

impl DIDResolverAdapter {
    pub fn new(did_resolver: Arc<Box<dyn DIDResolver>>) -> Self {
        DIDResolverAdapter { did_resolver }
    }
}

#[async_trait]
impl _DIDResolver for DIDResolverAdapter {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        let (cb, receiver) = OnDIDResolverResult::new();

        self.did_resolver.resolve(String::from(did), cb);

        let res = OnDIDResolverResult::get_result(receiver)
            .await
            .kind(ErrorKind::InvalidState, "can not resolve DID Doc")?;
        Ok(res)
    }
}
