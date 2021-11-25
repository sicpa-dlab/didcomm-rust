mod from_prior;
mod pack_encrypted;
mod pack_plaintext;
mod pack_signed;
mod protocols;
mod unpack;

pub use from_prior::{FromPriorExt, OnFromPriorPackResult, OnFromPriorUnpackResult};
pub use pack_encrypted::OnPackEncryptedResult;
pub use pack_plaintext::OnPackPlaintextResult;
pub use pack_signed::OnPackSignedResult;
pub use protocols::routing::OnWrapInForwardResult;
pub use unpack::OnUnpackResult;

use std::sync::Arc;

use crate::{FFIDIDResolver, FFISecretsResolver};

pub struct DIDComm {
    did_resolver: Arc<Box<dyn FFIDIDResolver>>,
    secret_resolver: Arc<Box<dyn FFISecretsResolver>>,
}

impl DIDComm {
    pub fn new(
        did_resolver: Box<dyn FFIDIDResolver>,
        secret_resolver: Box<dyn FFISecretsResolver>,
    ) -> Self {
        DIDComm {
            did_resolver: Arc::new(did_resolver),
            secret_resolver: Arc::new(secret_resolver),
        }
    }
}
