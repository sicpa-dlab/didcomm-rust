use lazy_static::lazy_static;
use serde_json::json;

use didcomm::secrets::{Secret, SecretMaterial, SecretType};

lazy_static! {
    pub(crate) static ref ALICE_SECRET_AUTH_KEY_ED25519: String = 
    serde_json::to_string(
    &Secret {
        id: "did:example:alice#key-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK(json!({
            "kty": "OKP",
            "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
            "crv": "Ed25519",
            "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
        })),
    }).unwrap();
    pub(crate) static ref ALICE_SECRET_AUTH_KEY_P256: String = 
    serde_json::to_string(
    &Secret {
        id: "did:example:alice#key-2".into(),
        type_: SecretType::JsonWebKey2020.into(),
        secret_material: SecretMaterial::JWK(json!({
            "kty": "EC",
            "d": "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
            "crv": "P-256",
            "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
            "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
        })),
    }).unwrap();
    pub(crate) static ref ALICE_SECRET_AUTH_KEY_SECP256K1: String =
    serde_json::to_string(
    &Secret {
        id: "did:example:alice#key-3".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK(json!({
            "kty": "EC",
            "d": "N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
            "crv": "secp256k1",
            "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
            "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk",
        })),
    }).unwrap();
    pub(crate) static ref ALICE_SECRET_KEY_AGREEMENT_KEY_X25519: String = 
    serde_json::to_string(
    &Secret {
        id: "did:example:alice#key-x25519-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK(json!({
            "kty": "OKP",
            "d": "r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
            "crv": "X25519",
            "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
        }),)
    }).unwrap();
    pub(crate) static ref ALICE_SECRET_KEY_AGREEMENT_KEY_P256: String = 
    serde_json::to_string(
    &Secret {
        id: "did:example:alice#key-p256-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK(json!({
            "kty": "EC",
            "d": "sB0bYtpaXyp-h17dDpMx91N3Du1AdN4z1FUq02GbmLw",
            "crv": "P-256",
            "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
            "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
        }))
    }).unwrap();
    pub(crate) static ref ALICE_SECRET_KEY_AGREEMENT_KEY_P521: String = 
    serde_json::to_string(
    &Secret {
        id: "did:example:alice#key-p521-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK(json!({
            "kty": "EC",
            "d": "AQCQKE7rZpxPnX9RgjXxeywrAMp1fJsyFe4cir1gWj-8t8xWaM_E2qBkTTzyjbRBu-JPXHe_auT850iYmE34SkWi",
            "crv": "P-521",
            "x": "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
            "y": "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk",
        })),
    }).unwrap();
    pub(crate) static ref ALICE_SECRETS: Vec<String> = vec![
        ALICE_SECRET_AUTH_KEY_ED25519.clone(),
        ALICE_SECRET_AUTH_KEY_P256.clone(),
        ALICE_SECRET_AUTH_KEY_SECP256K1.clone(),
        ALICE_SECRET_KEY_AGREEMENT_KEY_X25519.clone(),
        ALICE_SECRET_KEY_AGREEMENT_KEY_P256.clone(),
        ALICE_SECRET_KEY_AGREEMENT_KEY_P521.clone(),
    ];
}
