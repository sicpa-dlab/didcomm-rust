use lazy_static::lazy_static;

use crate::didcomm::secrets::Secret;

use super::{
    alice::{
        ALICE_SECRET_AUTH_KEY_ED25519,
        ALICE_SECRET_AUTH_KEY_P256,
        ALICE_SECRET_AUTH_KEY_SECP256K1,
        ALICE_SECRET_KEY_AGREEMENT_KEY_X25519,
        ALICE_SECRET_KEY_AGREEMENT_KEY_P256,
        ALICE_SECRET_KEY_AGREEMENT_KEY_P521,
    },
    charlie::{
        CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519,
        CHARLIE_SECRET_AUTH_KEY_ED25519,
    },
};

lazy_static! {
    pub(crate) static ref CHARLIE_ROTATED_TO_ALICE_SECRETS: Vec<Secret> = vec![
        CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519.clone(),
        CHARLIE_SECRET_AUTH_KEY_ED25519.clone(),
        ALICE_SECRET_AUTH_KEY_ED25519.clone(),
        ALICE_SECRET_AUTH_KEY_P256.clone(),
        ALICE_SECRET_AUTH_KEY_SECP256K1.clone(),
        ALICE_SECRET_KEY_AGREEMENT_KEY_X25519.clone(),
        ALICE_SECRET_KEY_AGREEMENT_KEY_P256.clone(),
        ALICE_SECRET_KEY_AGREEMENT_KEY_P521.clone(),
    ];
}
