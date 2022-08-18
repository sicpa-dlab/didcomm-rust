use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::did::{
    DIDCommMessagingService, DIDDoc, Service, ServiceKind, VerificationMaterial,
    VerificationMethod, VerificationMethodType,
};

lazy_static! {
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-x25519-1".into(),
            controller: "did:example:bob#key-x25519-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-x25519-2".into(),
            controller: "did:example:bob#key-x25519-2".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-x25519-3".into(),
            controller: "did:example:bob#key-x25519-3".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRETS_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-x25519-not-secrets-1".into(),
            controller: "did:example:bob#key-x25519-not-secrets-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-p256-1".into(),
            controller: "did:example:bob#key-p256-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                    "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-p256-2".into(),
            controller: "did:example:bob#key-p256-2".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                    "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_NOT_IN_SECRETS_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-p256-not-secrets-1".into(),
            controller: "did:example:bob#key-p256-not-secrets-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                    "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-p384-1".into(),
            controller: "did:example:bob#key-p384-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "EC",
                    "crv": "P-384",
                    "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                    "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-p384-2".into(),
            controller: "did:example:bob#key-p384-2".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "EC",
                    "crv": "P-384",
                    "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                    "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_NOT_IN_SECRETS_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-p384-not-secrets-1".into(),
            controller: "did:example:bob#key-p384-not-secrets-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "EC",
                    "crv": "P-384",
                    "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                    "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-p521-1".into(),
            controller: "did:example:bob#key-p521-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "EC",
                    "crv": "P-521",
                    "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                    "y": "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-p521-2".into(),
            controller: "did:example:bob#key-p521-2".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "EC",
                    "crv": "P-521",
                    "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                    "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH",
                })
            },
        };
    pub static ref BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_NOT_IN_SECRETS_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:bob#key-p521-not-secrets-1".into(),
            controller: "did:example:bob#key-p521-not-secrets-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!(
                {
                    "kty": "EC",
                    "crv": "P-521",
                    "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                    "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH",
                })
            },
        };
    pub static ref BOB_DID_COMM_MESSAGING_SERVICE: DIDCommMessagingService =
        DIDCommMessagingService {
            service_endpoint: "http://example.com/path".into(),
            accept: Some(vec!["didcomm/v2".into(), "didcomm/aip2;env=rfc587".into()]),
            routing_keys: vec!["did:example:mediator1#key-x25519-1".into()],
        };
    pub static ref BOB_SERVICE: Service = Service {
        id: "did:example:bob#didcomm-1".into(),
        kind: ServiceKind::DIDCommMessaging {
            value: BOB_DID_COMM_MESSAGING_SERVICE.clone()
        },
    };
    pub static ref BOB_DID_DOC: DIDDoc = DIDDoc {
        did: "did:example:bob".into(),
        authentications: vec![],
        key_agreements: vec![
            "did:example:bob#key-x25519-1".into(),
            "did:example:bob#key-x25519-2".into(),
            "did:example:bob#key-x25519-3".into(),
            "did:example:bob#key-p256-1".into(),
            "did:example:bob#key-p256-2".into(),
            "did:example:bob#key-p384-1".into(),
            "did:example:bob#key-p384-2".into(),
            "did:example:bob#key-p521-1".into(),
            "did:example:bob#key-p521-2".into(),
        ],
        services: vec![BOB_SERVICE.clone()],
        verification_methods: vec![
            BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2.clone(),
        ],
    };
    pub static ref BOB_DID_DOC_NO_SECRETS: DIDDoc = DIDDoc {
        did: "did:example:bob".into(),
        authentications: vec![],
        key_agreements: vec![
            "did:example:bob#key-x25519-1".into(),
            "did:example:bob#key-x25519-2".into(),
            "did:example:bob#key-x25519-3".into(),
            "did:example:bob#key-x25519-not-secrets-1".into(),
            "did:example:bob#key-p256-1".into(),
            "did:example:bob#key-p256-2".into(),
            "did:example:bob#key-p256-not-secrets-1".into(),
            "did:example:bob#key-p384-1".into(),
            "did:example:bob#key-p384-2".into(),
            "did:example:bob#key-p384-not-secrets-1".into(),
            "did:example:bob#key-p521-1".into(),
            "did:example:bob#key-p521-2".into(),
            "did:example:bob#key-p521-not-secrets-1".into(),
        ],
        services: vec![BOB_SERVICE.clone()],
        verification_methods: vec![
            BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRETS_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_NOT_IN_SECRETS_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_NOT_IN_SECRETS_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2.clone(),
            BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_NOT_IN_SECRETS_1.clone(),
        ],
    };
}
