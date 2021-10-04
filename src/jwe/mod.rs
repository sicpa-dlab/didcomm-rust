// TODO: remove allow
#[allow(dead_code)]
mod encrypt;

// TODO: remove allow
#[allow(dead_code)]
mod decrypt;

// TODO: remove allow
#[allow(dead_code)]
mod parse;

// TODO: remove allow
#[allow(dead_code)]
pub(crate) mod envelope;

// TODO: remove allow
#[allow(unused_imports)]
pub(crate) use encrypt::encrypt;

// TODO: remove allow
#[allow(unused_imports)]
pub(crate) use parse::{parse, ParsedJWE};

// TODO: remove allow
#[allow(unused_imports)]
pub(crate) use envelope::{Algorithm, EncAlgorithm};

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) const ALICE_KID_X25519_1: &str = "did:example:alice#key-x25519-1";

    pub(crate) const ALICE_KEY_X25519_1: &str = r#"{
        "kty":"OKP",
        "d":"r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
        "crv":"X25519",
        "x":"avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
     }"#;

    pub(crate) const ALICE_PKEY_X25519_1: &str = r#"{
        "kty":"OKP",
        "crv":"X25519",
        "x":"avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
     }"#;

    pub(crate) const ALICE_KID_P256_1: &str = "did:example:alice#key-p256-1";

    pub(crate) const ALICE_KEY_P256_1: &str = r#"{
        "kty":"EC",
        "d":"sB0bYtpaXyp-h17dDpMx91N3Du1AdN4z1FUq02GbmLw",
        "crv":"P-256",
        "x":"L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
        "y":"SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
    }"#;

    pub(crate) const ALICE_PKEY_P256_1: &str = r#"{
        "kty":"EC",
        "crv":"P-256",
        "x":"L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
        "y":"SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
    }"#;

    pub(crate) const BOB_KID_X25519_1: &str = "did:example:bob#key-x25519-1";

    pub(crate) const BOB_KEY_X25519_1: &str = r#"{
        "kty":"OKP",
        "d":"b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
        "crv":"X25519",
        "x":"GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E"
    }"#;

    pub(crate) const BOB_PKEY_X25519_1: &str = r#"{
        "kty":"OKP",
        "crv":"X25519",
        "x":"GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E"
    }"#;

    pub(crate) const BOB_KID_X25519_2: &str = "did:example:bob#key-x25519-2";

    pub(crate) const BOB_KEY_X25519_2: &str = r#"{
        "kty":"OKP",
        "d":"p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
        "crv":"X25519",
        "x":"UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
    }"#;

    pub(crate) const BOB_PKEY_X25519_2: &str = r#"{
        "kty":"OKP",
        "crv":"X25519",
        "x":"UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
    }"#;

    pub(crate) const BOB_KID_X25519_3: &str = "did:example:bob#key-x25519-3";

    pub(crate) const BOB_KEY_X25519_3: &str = r#"{
        "kty":"OKP",
        "d":"f9WJeuQXEItkGM8shN4dqFr5fLQLBasHnWZ-8dPaSo0",
        "crv":"X25519",
        "x":"82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
    }"#;

    pub(crate) const BOB_PKEY_X25519_3: &str = r#"{
        "kty":"OKP",
        "crv":"X25519",
        "x":"82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
    }"#;

    pub(crate) const BOB_KID_P256_1: &str = "did:example:bob#key-p256-1";

    pub(crate) const BOB_KEY_P256_1: &str = r#"{
        "kty":"EC",
        "d":"PgwHnlXxt8pwR6OCTUwwWx-P51BiLkFZyqHzquKddXQ",
        "crv":"P-256",
        "x":"FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
        "y":"6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY"
    }"#;

    pub(crate) const BOB_PKEY_P256_1: &str = r#"{
        "kty":"EC",
        "crv":"P-256",
        "x":"FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
        "y":"6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY"
    }"#;

    pub(crate) const BOB_KID_P256_2: &str = "did:example:bob#key-p256-2";

    pub(crate) const BOB_KEY_P256_2: &str = r#"{
        "kty":"EC",
        "d":"agKz7HS8mIwqO40Q2dwm_Zi70IdYFtonN5sZecQoxYU",
        "crv":"P-256",
        "x":"n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
        "y":"ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
    }"#;

    pub(crate) const BOB_PKEY_P256_2: &str = r#"{
        "kty":"EC",
        "crv":"P-256",
        "x":"n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
        "y":"ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
    }"#;
}
