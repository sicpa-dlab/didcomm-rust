use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::did::{
    DIDCommMessagingService, DIDDoc, Service, ServiceKind, VerificationMaterial,
    VerificationMethod, VerificationMethodType,
};

lazy_static! {
    pub static ref CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519: VerificationMethod =
        VerificationMethod {
            id: "did:example:charlie#key-x25519-1".into(),
            controller: "did:example:charlie#key-x25519-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::PublicKeyJwk {
                value: json!(
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw",
                })
            },
        };
    pub static ref CHARLIE_AUTH_METHOD_25519: VerificationMethod = VerificationMethod {
        id: "did:example:charlie#key-1".into(),
        controller: "did:example:charlie#key-1".into(),
        type_: VerificationMethodType::JsonWebKey2020,
        verification_material: VerificationMaterial::PublicKeyJwk {
            value: json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
            })
        },
    };
    pub static ref CHARLIE_DID_COMM_MESSAGING_SERVICE: DIDCommMessagingService =
        DIDCommMessagingService {
            uri: "did:example:mediator3".into(),
            accept: Some(vec!["didcomm/v2".into(), "didcomm/aip2;env=rfc587".into()]),
            routing_keys: vec![
                "did:example:mediator2#key-x25519-1".into(),
                "did:example:mediator1#key-x25519-1".into(),
            ],
        };
    pub static ref CHARLIE_SERVICE: Service = Service {
        id: "did:example:charlie#didcomm-1".into(),
        service_endpoint: ServiceKind::DIDCommMessaging {
            value: CHARLIE_DID_COMM_MESSAGING_SERVICE.clone()
        },
    };
    pub static ref CHARLIE_DID_DOC: DIDDoc = DIDDoc {
        id: "did:example:charlie".into(),
        authentication: vec!["did:example:charlie#key-1".into()],
        key_agreement: vec!["did:example:charlie#key-x25519-1".into()],
        service: vec![CHARLIE_SERVICE.clone()],
        verification_method: vec![
            CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519.clone(),
            CHARLIE_AUTH_METHOD_25519.clone(),
        ],
    };
}
