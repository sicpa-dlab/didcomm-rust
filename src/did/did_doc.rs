//! Set of interfaces that describe DID Document (https://www.w3.org/TR/did-core/)

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Represents DID Document (https://www.w3.org/TR/did-core/)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDDoc {
    /// DID for the given DID Doc
    pub id: String,

    /// DID URLs of verification methods used for key agreement.
    /// See https://www.w3.org/TR/did-core/#verification-methods.
    pub key_agreement: Vec<String>,

    /// Returns DID URLs of verification methods used for authentication.
    /// See https://www.w3.org/TR/did-core/#authentication
    pub authentication: Vec<String>,

    /// All local verification methods including embedded to
    /// key agreement and authentication sections.
    /// See https://www.w3.org/TR/did-core/#verification-methods.
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
    #[serde(flatten)]
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
#[serde(untagged)]
pub enum VerificationMaterial {
    #[serde(rename_all = "camelCase")]
    JWK { public_key_jwk: Value },

    #[serde(rename_all = "camelCase")]
    Multibase { public_key_multibase: String },

    #[serde(rename_all = "camelCase")]
    Base58 { public_key_base58: String },
}

/// Represents service record in DID Document (https://www.w3.org/TR/did-core/#services).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Service {
    pub id: String,

    #[serde(flatten)]
    pub service_endpoint: ServiceKind,
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
#[serde(rename_all = "camelCase")]
pub struct DIDCommMessagingService {
    pub uri: String,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<Vec<String>>,

    #[serde(default)]
    pub routing_keys: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SERVICE_URI: &str = "https://example.com/path";

    #[test]
    fn parsing_minimal_didcomm_messaging_service_works() {
        let service: DIDCommMessagingService =
            serde_json::from_value(json!({ "uri": SERVICE_URI })).unwrap();

        assert_eq!(service.uri, SERVICE_URI);
        assert!(service.routing_keys.is_empty());
        assert!(service.accept.is_none());
    }
}
