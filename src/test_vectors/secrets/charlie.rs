use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::secrets::{Secret, SecretMaterial, SecretType};

lazy_static! {
    pub(crate) static ref CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519: Secret = Secret {
        id: "did:example:charlie#key-x25519-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK(json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw",
            "d": "Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
        })),
    };
    pub(crate) static ref CHARLIE_SECRET_AUTH_KEY_ED25519: Secret = Secret {
        id: "did:example:charlie#key-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
            "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg",
        })),
    };
    pub(crate) static ref CHARLIE_SECRETS: Vec<Secret> = vec![
        CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519.clone(),
        CHARLIE_SECRET_AUTH_KEY_ED25519.clone(),
    ];
}
