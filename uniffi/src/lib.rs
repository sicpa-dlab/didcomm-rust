mod common;
mod did;
mod message;
mod secrets;

use std::sync::Arc;

pub use common::ErrorCode;
pub use common::JsonValue;
pub use did::resolvers::*;
pub use did::*;
pub use didcomm::algorithms::*;
pub use didcomm::did::*;
pub use didcomm::error::*;
pub use didcomm::secrets::*;
pub use didcomm::*;
pub use message::*;
pub use secrets::resolvers::*;
pub use secrets::*;

#[cfg(test)]
mod test_vectors;

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

uniffi_macros::include_scaffolding!("didcomm");
