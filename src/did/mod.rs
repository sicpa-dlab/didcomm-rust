pub(crate) mod did_doc;
pub(crate) mod did_resolver;

pub use did_doc::{
    DIDCommMessagingService, DIDDoc, PublicKey, Service, ServiceKind, VerificationMethod,
};

pub use did_resolver::DIDResolver;
