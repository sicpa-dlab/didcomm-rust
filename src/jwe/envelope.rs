use serde::{Deserialize, Serialize};
use serde_enum_str::{Deserialize_enum_str, Serialize_enum_str};
use serde_json::Value;

/// Subset of JWE in generic json serialization form used for authcrypt
/// and anoncrypt message types.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct JWE<'a> {
    /// BASE64URL(UTF8(JWE Protected Header))
    /// Note: this field value is used as AAD for JWE Ciphertext
    pub protected: &'a str,

    /// Array of recipient-specific objects
    pub recipients: Vec<Recepient<'a>>,

    /// BASE64URL(JWE Initialization Vector)
    pub iv: &'a str,

    /// BASE64URL(JWE Ciphertext)
    pub ciphertext: &'a str,

    /// BASE64URL(JWE Authentication Tag)
    pub tag: &'a str,
}

/// Protected header for authcrypt/anoncrypt-specific JWE.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct ProtectedHeader<'a> {
    /// Must be `application/didcomm-encrypted+json` or `didcomm-encrypted+json` for now.
    /// Something like `application/didcomm-encrypted+cbor` can be introduced in the
    /// future.
    pub typ: &'a str,

    /// Cryptographic algorithm used to encrypt or determine the value of the CEK.
    pub alg: Algorithm,

    /// Identifies the content encryption algorithm used to perform authenticated encryption
    /// on the plaintext to produce the ciphertext and the Authentication Tag.
    pub enc: EncAlgorithm,

    /// Sender KID as DID Url.
    /// If absent implementations MUST be able to resolve the sender kid from the `apu` header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skid: Option<&'a str>,

    /// BASE64URL("skid" header value),
    pub apu: Option<&'a str>,

    /// BASE64URL(SHA256(CONCAT('.', SORT([recipients[0].kid, ..., recipients[n].kid])))))
    pub apv: &'a str,

    /// EPK generated once for all recipients.
    /// It MUST be of the same type and curve as all recipient keys since kdf
    /// with the sender key must be on the same curve.
    pub epk: Value,
}
/// Recipient part of authcrypt/anoncrypt-specific JWE
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Recepient<'a> {
    /// Per-recipient header
    /// Note it isn't serialized and not integrity protected
    pub header: PerRecipientHeader<'a>,

    /// BASE64URL(JWE Encrypted Key)
    pub encrypted_key: &'a str,
}

/// Per-recipient header part of authcrypt/anoncrypt-specific JWE
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct PerRecipientHeader<'a> {
    /// Recipient KID as DID URL
    pub kid: &'a str,
}

/// Represents possible values for `alg` header.
/// Cryptographic algorithm used to encrypt or determine the value of the CEK.
#[derive(Deserialize_enum_str, Serialize_enum_str, Debug, Clone, Eq, PartialEq)]
pub(crate) enum Algorithm {
    #[serde(rename = "ECDH-1PU+A256KW")]
    Ecdh1puA256kw,

    #[serde(rename = "ECDH-ES+A256KW")]
    Ecdh1esA256kw,

    #[serde(other)]
    Other(String),
}

/// Represents possible values for `enc` header.
/// Identifies the content encryption algorithm used to perform authenticated encryption
/// on the plaintext to produce the ciphertext and the Authentication Tag.
#[derive(Deserialize_enum_str, Serialize_enum_str, Debug, Clone, Eq, PartialEq)]
pub(crate) enum EncAlgorithm {
    #[serde(rename = "A256CBC-HS512")]
    A256cbcHs512,

    #[serde(rename = "XC20P")]
    Xc20P,

    #[serde(rename = "A256GCM")]
    A256Gcm,

    #[serde(other)]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorythm_serialize_works() {
        let alg = Algorithm::Ecdh1puA256kw;
        let alg = serde_json::to_string(&alg).expect("unable serialize.");
        assert_eq!(alg, "\"ECDH-1PU+A256KW\"");

        let alg = Algorithm::Other("Unknown".into());
        let alg = serde_json::to_string(&alg).expect("unable serialize.");
        assert_eq!(alg, "\"Unknown\"");
    }

    #[test]
    fn algorythm_deserialize_works() {
        let alg: Algorithm =
            serde_json::from_str("\"ECDH-1PU+A256KW\"").expect("unable deserialize.");

        assert_eq!(alg, Algorithm::Ecdh1puA256kw);

        let alg: Algorithm = serde_json::from_str("\"Unknown\"").expect("unable deserialize.");
        assert_eq!(alg, Algorithm::Other("Unknown".into()));

        let alg: Algorithm = serde_json::from_str("\"Unknown 2\"").expect("unable deserialize.");
        assert_eq!(alg, Algorithm::Other("Unknown 2".into()));
    }

    #[test]
    fn enc_algorythm_serialize_works() {
        let enc_alg = EncAlgorithm::A256cbcHs512;
        let enc_alg = serde_json::to_string(&enc_alg).expect("unable serialize.");
        assert_eq!(enc_alg, "\"A256CBC-HS512\"");

        let enc_alg = EncAlgorithm::Other("Unknown".into());
        let enc_alg = serde_json::to_string(&enc_alg).expect("unable serialize.");
        assert_eq!(enc_alg, "\"Unknown\"");
    }

    #[test]
    fn enc_algorythm_deserialize_works() {
        let enc_alg: EncAlgorithm =
            serde_json::from_str("\"A256CBC-HS512\"").expect("unable deserialize.");

        assert_eq!(enc_alg, EncAlgorithm::A256cbcHs512);

        let enc_alg: EncAlgorithm =
            serde_json::from_str("\"Unknown\"").expect("unable deserialize.");

        assert_eq!(enc_alg, EncAlgorithm::Other("Unknown".into()));

        let enc_alg: EncAlgorithm =
            serde_json::from_str("\"Unknown 2\"").expect("unable deserialize.");

        assert_eq!(enc_alg, EncAlgorithm::Other("Unknown 2".into()));
    }
}
