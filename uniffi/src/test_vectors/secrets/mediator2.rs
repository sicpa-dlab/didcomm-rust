use lazy_static::lazy_static;
use serde_json::json;

use didcomm::secrets::{Secret, SecretMaterial, SecretType};

lazy_static! {
    pub(crate) static ref MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_X25519_1: Secret = Secret {
        id: "did:example:mediator2#key-x25519-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            value: json!(
            {
                "kty": "OKP",
                "d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
                "crv": "X25519",
                "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
            })
        },
    };
    pub(crate) static ref MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P256_1: Secret = Secret {
        id: "did:example:mediator2#key-p256-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            value: json!(
            {
                "kty": "EC",
                "d": "PgwHnlXxt8pwR6OCTUwwWx-P51BiLkFZyqHzquKddXQ",
                "crv": "P-256",
                "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
            })
        },
    };
    pub(crate) static ref MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P384_1: Secret = Secret {
        id: "did:example:mediator2#key-p384-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            value: json!(
            {
                "kty": "EC",
                "d": "ajqcWbYA0UDBKfAhkSkeiVjMMt8l-5rcknvEv9t_Os6M8s-HisdywvNCX4CGd_xY",
                "crv": "P-384",
                "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7",
            })
        },
    };
    pub(crate) static ref MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P521_1: Secret = Secret {
        id: "did:example:mediator2#key-p521-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            value: json!(
            {
                "kty": "EC",
                "d": "AV5ocjvy7PkPgNrSuvCxtG70NMj6iTabvvjSLbsdd8OdI9HlXYlFR7RdBbgLUTruvaIRhjEAE9gNTH6rWUIdfuj6",
                "crv": "P-521",
                "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                "y": "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH",
            })
        },
    };
    pub(crate) static ref MEDIATOR2_SECRETS: Vec<Secret> = vec![
        MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_X25519_1.clone(),
        MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P256_1.clone(),
        MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P384_1.clone(),
        MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P521_1.clone(),
    ];
}
