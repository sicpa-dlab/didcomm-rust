mod from_prior;
mod pack_encrypted;
mod pack_plaintext;
mod pack_signed;
mod protocols;
mod unpack;

pub use from_prior::{OnFromPriorPackResult, OnFromPriorUnpackResult};
pub use pack_encrypted::OnPackEncryptedResult;
pub use pack_plaintext::OnPackPlaintextResult;
pub use pack_signed::OnPackSignedResult;
pub use protocols::routing::OnWrapInForwardResult;
pub use unpack::OnUnpackResult;

use std::sync::Arc;

use crate::{DIDResolver, KeyManagementService};

pub struct DIDComm {
    did_resolver: Arc<Box<dyn DIDResolver>>,
    kms: Arc<Box<dyn KeyManagementService>>,
}

impl DIDComm {
    pub fn new(did_resolver: Box<dyn DIDResolver>, kms: Box<dyn KeyManagementService>) -> Self {
        DIDComm {
            did_resolver: Arc::new(did_resolver),
            kms: Arc::new(kms),
        }
    }
}
