use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};

use didcomm::{
    did::{DIDDoc, DIDResolver},
    error::{ErrorKind, Result, ResultExt},
};
use futures::channel::oneshot;

use crate::{did_resolver::OnDIDResolverResult, FFIDIDResolver};

use async_trait::async_trait;

pub(crate) struct FFIDIDResolverAdapter {
    did_resolver: Arc<Box<dyn FFIDIDResolver>>,
}

impl FFIDIDResolverAdapter {
    pub fn new(did_resolver: Arc<Box<dyn FFIDIDResolver>>) -> Self {
        FFIDIDResolverAdapter { did_resolver }
    }
}

#[async_trait]
impl DIDResolver for FFIDIDResolverAdapter {
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
