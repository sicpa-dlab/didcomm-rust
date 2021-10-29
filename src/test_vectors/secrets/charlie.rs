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
            "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
            "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
        })),
    };
    pub(crate) static ref CHARLIE_SECRETS: Vec<Secret> = vec![
        CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519.clone(),
        CHARLIE_SECRET_AUTH_KEY_ED25519.clone(),
    ];
}
