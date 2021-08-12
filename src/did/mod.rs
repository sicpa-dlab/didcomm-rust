pub mod resolvers;

pub(crate) mod did_doc;
pub(crate) mod did_resolver;

pub use did_doc::{
    DIDCommMessagingService, DIDDoc, Service, ServiceKind, VerificationMatherial,
    VerificationMethod,
};

pub use did_resolver::DIDResolver;
