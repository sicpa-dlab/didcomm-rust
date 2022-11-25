use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::did::{
    DIDDoc, VerificationMaterial, VerificationMethod, VerificationMethodType,
};

lazy_static! {
    pub static ref ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET: VerificationMethod =
        VerificationMethod {
            id: "did:example:alice#key-x25519-not-in-secrets-1".into(),
            controller: "did:example:alice#key-x25519-not-in-secrets-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!({
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
                })
            },
        };
    pub static ref ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519: VerificationMethod =
        VerificationMethod {
            id: "did:example:alice#key-x25519-1".into(),
            controller: "did:example:alice#key-x25519-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!({
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
                })
            },
        };
    pub static ref ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256: VerificationMethod =
        VerificationMethod {
            id: "did:example:alice#key-p256-1".into(),
            controller: "did:example:alice#key-p256-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                    "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
                })
            },
        };
    pub static ref ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521: VerificationMethod =
        VerificationMethod {
            id: "did:example:alice#key-p521-1".into(),
            controller: "did:example:alice#key-p521-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                value: json!({
                    "kty": "EC",
                    "crv": "P-521",
                    "x": "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
                    "y": "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk",
                })
            },
        };
    pub static ref ALICE_AUTH_METHOD_25519_NOT_IN_SECRET: VerificationMethod = VerificationMethod {
        id: "did:example:alice#key-not-in-secrets-1".into(),
        controller: "did:example:alice#key-not-in-secrets-1".into(),
        type_: VerificationMethodType::JsonWebKey2020,
        verification_material: VerificationMaterial::JWK {
            value: json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
            })
        },
    };
    pub static ref ALICE_AUTH_METHOD_25519: VerificationMethod = VerificationMethod {
        id: "did:example:alice#key-1".into(),
        controller: "did:example:alice#key-1".into(),
        type_: VerificationMethodType::JsonWebKey2020,
        verification_material: VerificationMaterial::JWK {
            value: json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
            })
        },
    };
    pub static ref ALICE_AUTH_METHOD_P256: VerificationMethod = VerificationMethod {
        id: "did:example:alice#key-2".into(),
        controller: "did:example:alice#key-2".into(),
        type_: VerificationMethodType::JsonWebKey2020,
        verification_material: VerificationMaterial::JWK {
            value: json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
            })
        },
    };
    pub static ref ALICE_AUTH_METHOD_SECPP256K1: VerificationMethod = VerificationMethod {
        id: "did:example:alice#key-3".into(),
        controller: "did:example:alice#key-3".into(),
        type_: VerificationMethodType::JsonWebKey2020,
        verification_material: VerificationMaterial::JWK {
            value: json!({
                "kty": "EC",
                "crv": "secp256k1",
                "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
                "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk",
            })
        },
    };
    pub static ref ALICE_DID_DOC: DIDDoc = DIDDoc {
        id: "did:example:alice".into(),
        authentication: vec![
            "did:example:alice#key-1".into(),
            "did:example:alice#key-2".into(),
            "did:example:alice#key-3".into(),
        ],
        key_agreement: vec![
            "did:example:alice#key-x25519-not-in-secrets-1".into(),
            "did:example:alice#key-x25519-1".into(),
            "did:example:alice#key-p256-1".into(),
            "did:example:alice#key-p521-1".into(),
        ],
        service: vec![],
        verification_method: vec![
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.clone(),
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.clone(),
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521.clone(),
            ALICE_AUTH_METHOD_25519_NOT_IN_SECRET.clone(),
            ALICE_AUTH_METHOD_25519.clone(),
            ALICE_AUTH_METHOD_P256.clone(),
            ALICE_AUTH_METHOD_SECPP256K1.clone(),
        ],
    };
    pub static ref ALICE_DID_DOC_WITH_NO_SECRETS: DIDDoc = DIDDoc {
        id: "did:example:alice".into(),
        authentication: vec![
            "did:example:alice#key-not-in-secrets-1".into(),
            "did:example:alice#key-1".into(),
            "did:example:alice#key-2".into(),
            "did:example:alice#key-3".into(),
        ],
        key_agreement: vec![
            "did:example:alice#key-x25519-not-in-secrets-1".into(),
            "did:example:alice#key-x25519-1".into(),
            "did:example:alice#key-p256-1".into(),
            "did:example:alice#key-p521-1".into(),
        ],
        service: vec![],
        verification_method: vec![
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET.clone(),
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.clone(),
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.clone(),
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521.clone(),
            ALICE_AUTH_METHOD_25519_NOT_IN_SECRET.clone(),
            ALICE_AUTH_METHOD_25519.clone(),
            ALICE_AUTH_METHOD_P256.clone(),
            ALICE_AUTH_METHOD_SECPP256K1.clone(),
        ],
    };
}
