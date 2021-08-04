//! Set of intrfaces that describe DID Document (https://www.w3.org/TR/did-core/)

use crate::error::Result;

/// Represents DID Document (https://www.w3.org/TR/did-core/#dfn-did-documents)
pub trait DIDDoc {
    fn key_agreements(&self) -> Vec<Box<dyn DIDKeyAgreement>>;
    fn key_agreement(&self, kid: &str) -> Box<dyn DIDKeyAgreement>;
    fn authentications(&self) -> Vec<Box<dyn DIDAuthentication>>;
    fn authentication(&self, kid: &str) -> Box<dyn DIDAuthentication>;
    fn endpoints(&self) -> Vec<Box<dyn DIDEndpoint>>;
}

/// Represents KeyAgreement record in DID Document  (https://www.w3.org/TR/did-core/#key-agreement)
pub trait DIDKeyAgreement {
    /// Returns key agreement crypto material as JWK
    fn as_jwk(&self) -> Result<String>; // public JWK
}

/// Represents Authentication record in DID Document (https://www.w3.org/TR/did-core/#authentication)
pub trait DIDAuthentication {
     /// Returns authentication crypto material as JWK
    fn as_jwk(&self) -> Result<String>; // public JWK
}

/// Represents endpoint record in DID Document (FIXME: provide link)
pub trait DIDEndpoint {
    /// Returns route key assotiated with this endpoint
    fn route_key(&self) -> Option<Box<dyn DIDRouteKey>>; // public JWK
}

/// Represents RouteKey record in DID Document (FIXME: provide link)
pub trait DIDRouteKey {
    /// Returns rotue key crypto material as JWK
    fn as_jwk(&self) -> Result<String>; // public JWK
}
