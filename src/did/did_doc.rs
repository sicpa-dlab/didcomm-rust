//! Set of interfaces that describe DID Document (https://www.w3.org/TR/did-core/)

use serde_json::Value;

/// Represents DID Document (https://www.w3.org/TR/did-core/)
pub trait DIDDoc {
    /// Returns DID URLs of verification methods used for key agreement.
    /// See https://www.w3.org/TR/did-core/#verification-methods.
    fn key_agreements(&self) -> &[String];

    /// Returns DID URLs of verification methods used for authentication.
    /// See https://www.w3.org/TR/did-core/#authentication
    fn authentications(&self) -> &[String];

    /// Returns all local verification methods including embedded to
    /// key agreement and authentication sections.
    /// See https://www.w3.org/TR/did-core/#verification-methods.
    fn verification_methods(&self) -> &[VerificationMethod];

    /// Returns all services (https://www.w3.org/TR/did-core/#services)
    fn services(&self) -> &[Service];
}

/// Represents verification method record in DID Document
/// (https://www.w3.org/TR/did-core/#verification-methods).
pub struct VerificationMethod {
    pub id: String,
    pub type_: String,
    pub controller: String,
    pub public_key: PublicKey,
}

/// Represents verification material (https://www.w3.org/TR/did-core/#verification-material)
pub enum PublicKey {
    JWK(Value),
    Multibase(String),
}

/// Represents service record in DID Document (https://www.w3.org/TR/did-core/#services).
pub struct Service {
    pub id: String,
    pub type_: String,
    pub service_endpoint: Vec<String>,
    pub kind: ServiceKind,
}

/// Represents additional service properties defined for specific Service type.
pub enum ServiceKind {
    DIDCommMessaging(DIDCommMessagingService),
    Other(Value),
}

/// Properties for DIDCommMessagingService
/// (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
pub struct DIDCommMessagingService {
    pub accept: Vec<String>,
    pub route_keys: Vec<String>,
}
