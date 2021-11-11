use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::did::{
    DIDDoc, VerificationMaterial, VerificationMethod, VerificationMethodType,
};

lazy_static! {
    pub(crate) static ref CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519: VerificationMethod =
        VerificationMethod {
            id: "did:example:charlie#key-x25519-1".into(),
            controller: "did:example:charlie#key-x25519-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK(json!(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw",
            })),
        };
    pub(crate) static ref CHARLIE_AUTH_METHOD_25519: VerificationMethod = VerificationMethod {
        id: "did:example:charlie#key-1".into(),
        controller: "did:example:charlie#key-1".into(),
        type_: VerificationMethodType::JsonWebKey2020,
        verification_material: VerificationMaterial::JWK(json!(
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
        })),
    };
    pub(crate) static ref CHARLIE_DID_DOC: DIDDoc = DIDDoc {
        did: "did:example:charlie".into(),
        authentications: vec!["did:example:charlie#key-1".into(),],
        key_agreements: vec!["did:example:charlie#key-x25519-1".into(),],
        services: vec![],
        verification_methods: vec![
            CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519.clone(),
            CHARLIE_AUTH_METHOD_25519.clone(),
        ],
    };
}
