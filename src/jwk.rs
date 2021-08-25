use askar_crypto::jwk::JwkParts;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ErrorKind, Result, ResultExt};

/// TODO: FIXME: Think on how to integrate better with JwkParts<'a>
/// without re-serialization
#[derive(Debug, Clone)]
pub(crate) struct JWK(String);

impl JWK {
    pub fn _parts(&self) -> Result<JwkParts> {
        JwkParts::from_str(&self.0).kind(ErrorKind::Malformed, "jwl malformed.")
    }
}

impl Serialize for JWK {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value: Value =
            serde_json::from_str(&self.0).map_err(|e| serde::ser::Error::custom(e.to_string()))?;

        Serialize::serialize(&value, s)
    }
}

impl<'de> Deserialize<'de> for JWK {
    fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let jwk: Value = Deserialize::deserialize(d)?;

        let jwk =
            serde_json::to_string(&jwk).map_err(|e| serde::de::Error::custom(e.to_string()))?;

        Ok(JWK(jwk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_works() {
        let jwk = JWK(r#"{"crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","key_ops":["sign","verify"],"kid":"FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#.into());

        let jwk = serde_json::to_string(&jwk).expect("unable serialise.");

        assert_eq!(
            jwk,
            r#"{"crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","key_ops":["sign","verify"],"kid":"FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
        );
    }

    #[test]
    fn deserialize_works() {
        let jwk: JWK = serde_json::from_str(
            r#"{
            "crv":"Ed25519",
            "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "key_ops":["sign","verify"],
            "kid":"FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ",
            "kty":"OKP",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }"#,
        )
        .expect("unable serialise.");

        assert_eq!(
            jwk.0,
            r#"{"crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","key_ops":["sign","verify"],"kid":"FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
        );
    }
}
