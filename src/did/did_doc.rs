//! Set of interfaces that describe DID Document (https://www.w3.org/TR/did-core/)

use serde_json::Value;

/// Represents DID Document (https://www.w3.org/TR/did-core/)
#[derive(Debug, Clone)]
pub struct DIDDoc {
    /// DID for the given DID Doc
    pub(crate) did: String,

    /// DID URLs of verification methods used for key agreement.
    /// See https://www.w3.org/TR/did-core/#verification-methods.
    // TODO: Remove allow
    #[allow(dead_code)]
    pub(crate) key_agreements: Vec<String>,

    /// Returns DID URLs of verification methods used for authentication.
    /// See https://www.w3.org/TR/did-core/#authentication
    pub(crate) authentications: Vec<String>,

    /// All local verification methods including embedded to
    /// key agreement and authentication sections.
    /// See https://www.w3.org/TR/did-core/#verification-methods.
    // TODO: Remove allow
    #[allow(dead_code)]
    pub(crate) verification_methods: Vec<VerificationMethod>,

    /// All services (https://www.w3.org/TR/did-core/#services)
    // TODO: Remove allow
    #[allow(dead_code)]
    pub(crate) services: Vec<Service>,
}

/// Represents verification method record in DID Document
/// (https://www.w3.org/TR/did-core/#verification-methods).
#[derive(Clone, Debug)]
pub struct VerificationMethod {
    pub id: String,
    pub type_: VerificationMethodType,
    pub controller: String,
    pub verification_material: VerificationMaterial,
}

#[derive(Clone, Debug)]
pub enum VerificationMethodType {
    JsonWebKey2020,
    X25519KeyAgreementKey2019,
    Ed25519VerificationKey2018,
    EcdsaSecp256k1VerificationKey2019,
    Other(String),
}

/// Represents verification material (https://www.w3.org/TR/did-core/#verification-material)
#[derive(Clone, Debug)]
pub enum VerificationMaterial {
    JWK(Value),
    Multibase(String),
    Base58(String),
    Hex(String),
    Other(Value),
}

/// Represents service record in DID Document (https://www.w3.org/TR/did-core/#services).
#[derive(Clone, Debug)]
pub struct Service {
    pub id: String,
    pub type_: String,
    pub kind: ServiceKind,
}

/// Represents additional service properties defined for specific Service type.
#[derive(Clone, Debug)]
pub enum ServiceKind {
    DIDCommMessaging(DIDCommMessagingService),
    Other(Value),
}

/// Properties for DIDCommMessagingService
/// (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
#[derive(Clone, Debug)]
pub struct DIDCommMessagingService {
    pub service_endpoint: String,
    pub accept: Vec<String>,
    pub route_keys: Vec<String>,
}
