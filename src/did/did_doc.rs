//! Set of interfaces that describe DID Document (https://www.w3.org/TR/did-core/)

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Represents DID Document (https://www.w3.org/TR/did-core/)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DIDDoc {
    /// DID for the given DID Doc
    pub did: String,

    /// DID URLs of verification methods used for key agreement.
    /// See https://www.w3.org/TR/did-core/#verification-methods.
    pub key_agreements: Vec<String>,

    /// Returns DID URLs of verification methods used for authentication.
    /// See https://www.w3.org/TR/did-core/#authentication
    pub authentications: Vec<String>,

    /// All local verification methods including embedded to
    /// key agreement and authentication sections.
    /// See https://www.w3.org/TR/did-core/#verification-methods.
    pub verification_methods: Vec<VerificationMethod>,

    /// All services (https://www.w3.org/TR/did-core/#services)
    pub services: Vec<Service>,
}

/// Represents verification method record in DID Document
/// (https://www.w3.org/TR/did-core/#verification-methods).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: VerificationMethodType,
    pub controller: String,
    pub verification_material: VerificationMaterial,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum VerificationMethodType {
    JsonWebKey2020,
    X25519KeyAgreementKey2019,
    Ed25519VerificationKey2018,
    EcdsaSecp256k1VerificationKey2019,
    X25519KeyAgreementKey2020,
    Ed25519VerificationKey2020,
    Other,
}

/// Represents verification material (https://www.w3.org/TR/did-core/#verification-material)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "format")]
pub enum VerificationMaterial {
    JWK { value: Value },
    Multibase { value: String },
    Base58 { value: String },
    Hex { value: String },
    Other { value: Value },
}

/// Represents service record in DID Document (https://www.w3.org/TR/did-core/#services).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Service {
    pub id: String,
    pub kind: ServiceKind,
}

/// Represents additional service properties defined for specific Service type.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ServiceKind {
    DIDCommMessaging {
        #[serde(flatten)]
        value: DIDCommMessagingService,
    },
    Other {
        #[serde(flatten)]
        value: Value,
    },
}

/// Properties for DIDCommMessagingService
/// (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DIDCommMessagingService {
    pub service_endpoint: String,
    pub accept: Vec<String>,
    pub routing_keys: Vec<String>,
}
