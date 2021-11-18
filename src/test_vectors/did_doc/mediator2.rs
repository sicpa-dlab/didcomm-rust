use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::did::{
    DIDDoc, VerificationMaterial, VerificationMethod, VerificationMethodType,
};

lazy_static! {
    pub(crate) static ref MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:mediator2#key-x25519-1".into(),
            controller: "did:example:mediator2#key-x25519-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK(json!(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
            })),
        };
    pub(crate) static ref MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:mediator2#key-p256-1".into(),
            controller: "did:example:mediator2#key-p256-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK(json!(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
            })),
        };
    pub(crate) static ref MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:mediator2#key-p384-1".into(),
            controller: "did:example:mediator2#key-p384-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK(json!(
            {
                "kty": "EC",
                "crv": "P-384",
                "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7",
            })),
        };
    pub(crate) static ref MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:mediator2#key-p521-1".into(),
            controller: "did:example:mediator2#key-p521-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK(json!(
            {
                "kty": "EC",
                "crv": "P-521",
                "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                "y": "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH",
            })),
        };
    pub(crate) static ref MEDIATOR2_DID_DOC: DIDDoc = DIDDoc {
        did: "did:example:mediator2".into(),
        authentications: vec![],
        key_agreements: vec![
            "did:example:mediator2#key-x25519-1".into(),
            "did:example:mediator2#key-p256-1".into(),
            "did:example:mediator2#key-p384-1".into(),
            "did:example:mediator2#key-p521-1".into(),
        ],
        services: vec![],
        verification_methods: vec![
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1.clone(),
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1.clone(),
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1.clone(),
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1.clone(),
        ],
    };
}
