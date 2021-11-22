use async_trait::async_trait;
use std::cell::RefCell;
use std::sync::Mutex;

use crate::did::{DIDDoc, DIDResolver};

pub struct MockDidResolver {
    results: Mutex<RefCell<Vec<crate::error::Result<Option<DIDDoc>>>>>,
}

impl MockDidResolver {
    pub fn new(res: Vec<crate::error::Result<Option<DIDDoc>>>) -> Self {
        Self {
            results: Mutex::new(RefCell::new(res)),
        }
    }
}

#[cfg_attr(feature = "uniffi", async_trait)]
#[cfg_attr(not(feature = "uniffi"), async_trait(?Send))]
impl DIDResolver for MockDidResolver {
    async fn resolve(&self, _did: &str) -> crate::error::Result<Option<DIDDoc>> {
        self.results.lock().unwrap().borrow_mut().pop().unwrap()
    }
}
