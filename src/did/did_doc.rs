//! Set of interfaces that describe DID Document (https://www.w3.org/TR/did-core/)

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Represents DID Document (https://www.w3.org/TR/did-core/)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DIDDoc {
    /// DID for the given DID Doc
    pub id: String,

    /// DID URLs of verification methods used for key agreement.
    /// See https://www.w3.org/TR/did-core/#verification-methods.
    #[serde(rename = "keyAgreement")]
    pub key_agreement: Vec<String>,

    /// Returns DID URLs of verification methods used for authentication.
    /// See https://www.w3.org/TR/did-core/#authentication
    pub authentication: Vec<String>,

    /// All local verification methods including embedded to
    /// key agreement and authentication sections.
    /// See https://www.w3.org/TR/did-core/#verification-methods.
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,

    /// All services (https://www.w3.org/TR/did-core/#services)
    pub service: Vec<Service>,
}

/// Represents verification method record in DID Document
/// (https://www.w3.org/TR/did-core/#verification-methods).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: VerificationMethodType,
    pub controller: String,
    // TODO: this should be publicKeyJwk/publicKeyMultibase
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

    #[serde(flatten)]
    pub service_endpoint: ServiceKind,

}

#[cfg(test)]
mod tests {
    use crate::did::{DIDCommMessagingService, Service, ServiceKind};

    #[test]
    fn test_display_service() {
        println!("{}", serde_json::to_string(&Service{
            id: "test".into(),
            service_endpoint: ServiceKind::DIDCommMessaging {
                value: DIDCommMessagingService {
                    uri: "demo".into(),
                    routing_keys: vec!["test".into()],
                    accept: None,
                }
            }
        }).unwrap())
    }
}

/// Represents additional service properties defined for specific Service type.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", content = "serviceEndpoint")]
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
    pub uri: String,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<Vec<String>>,

    #[serde(rename = "routingKeys")]
    pub routing_keys: Vec<String>,
}
