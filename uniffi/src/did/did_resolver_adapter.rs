use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};

use didcomm_core::{
    did::{DIDDoc, DIDResolver as _DIDResolver},
    error::{ErrorKind, Result, ResultExt},
};
use futures::channel::oneshot;

use crate::{did_resolver::OnDIDResolverResult, DIDResolver};

use async_trait::async_trait;

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
        let (sender, receiver) = oneshot::channel::<Result<Option<DIDDoc>>>();

        let cb = Arc::new(OnDIDResolverResult::new(Mutex::new(RefCell::new(Some(
            sender,
        )))));

        self.did_resolver.resolve(String::from(did), cb);

        let res = receiver
            .await
            .kind(ErrorKind::InvalidState, "can not resolve DID Doc")?
            .kind(ErrorKind::InvalidState, "can not resolve DID Doc")?;

        Ok(res)
    }
}
