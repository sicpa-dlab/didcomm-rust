use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair, x25519::X25519KeyPair},
    jwk::{FromJwk, ToJwk},
};

use serde_json::Value;

use crate::error::{ErrorKind, Result, ResultExt};

pub(crate) trait FromJwkValue: FromJwk {
    /// Import the key from a JWK string reference
    fn from_jwk_value(jwk: &Value) -> Result<Self> {
        let jwk = serde_json::to_string(jwk)
            .kind(ErrorKind::InvalidState, "Unable produce jwk string")?;

        Self::from_jwk(&jwk).kind(ErrorKind::Malformed, "Unable produce jwk")
    }
}

pub(crate) trait ToJwkValue: ToJwk {
    fn to_jwk_public_value(&self) -> Result<Value> {
        let jwk = self
            .to_jwk_public(None)
            .kind(ErrorKind::InvalidState, "Unable produce jwk string")?;

        let jwk: Value =
            serde_json::from_str(&jwk).kind(ErrorKind::InvalidState, "Unable produce jwk value")?;

        Ok(jwk)
    }
}

impl FromJwkValue for Ed25519KeyPair {}
impl FromJwkValue for P256KeyPair {}
impl FromJwkValue for X25519KeyPair {}
impl FromJwkValue for K256KeyPair {}

impl ToJwkValue for Ed25519KeyPair {}
impl ToJwkValue for P256KeyPair {}
impl ToJwkValue for X25519KeyPair {}

#[cfg(test)]
mod tests {
    use askar_crypto::alg::ed25519::Ed25519KeyPair;
    use serde_json::json;

    use super::*;

    #[test]
    fn from_to_jwk_value_works() {
        let jwk = json!({
            "crv":"Ed25519",
            "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "key_ops":["sign","verify"],
            "kid":"FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ",
            "kty":"OKP",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });

        let key = Ed25519KeyPair::from_jwk_value(&jwk).expect("unable from_jwk_value");

        let pub_jwk = key
            .to_jwk_public_value()
            .expect("unable to_jwk_public_value");

        assert_eq!(
            pub_jwk,
            json!({
                "crv":"Ed25519",
                "kty":"OKP",
                "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            })
        );
    }
}
