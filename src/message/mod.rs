pub use attachment::{
    Attachment, AttachmentBuilder, AttachmentData, Base64AttachmentData, JsonAttachmentData,
    LinksAttachmentData,
};
pub use message::{Message, MessageBuilder};
pub use pack_encrypted::{PackEncryptedMetadata, PackEncryptedOptions};
pub use pack_signed::PackSignedMetadata;
pub use unpack::{UnpackMetadata, UnpackOptions};

use crate::did::{DIDDoc, DIDResolver};

mod attachment;
mod message;
mod pack_encrypted;
mod pack_plaintext;
mod pack_signed;
mod unpack;

use std::cell::RefCell;
use std::sync::Mutex;

struct MockDidResolver {
    results: Mutex<RefCell<Vec<crate::error::Result<Option<DIDDoc>>>>>,
}

impl MockDidResolver {
    fn new(res: Vec<crate::error::Result<Option<DIDDoc>>>) -> Self {
        Self {
            results: Mutex::new(RefCell::new(res)),
        }
    }
}

#[async_trait::async_trait]
impl DIDResolver for MockDidResolver {
    async fn resolve(&self, _did: &str) -> crate::error::Result<Option<DIDDoc>> {
        self.results.lock().unwrap().borrow_mut().pop().unwrap()
    }
}
