pub(crate) mod did_doc;
pub(crate) mod did_resolver;

pub use did_doc::{DIDAuthentication, DIDDoc, DIDEndpoint, DIDKeyAgreement, DIDRouteKey};
pub use did_resolver::DIDResolver;
