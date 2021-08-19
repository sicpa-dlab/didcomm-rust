use serde::{Deserialize, Serialize};

use crate::{
    jwk::JWK,
    utils::base64::{Base64Binary, Base64Json},
};

/// Subset of JWE in generic json serialization form used for authcrypt.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct JWE {
    /// BASE64URL(UTF8(JWE Protected Header))
    /// Note: this field value is used as AAD for JWE Ciphertext
    protected: Base64Json<ProtectedHeader>,

    /// Array of recipient-specific objects
    pub recipients: Vec<Recepient>,

    /// BASE64URL(JWE Initialization Vector)
    pub iv: Base64Binary<Vec<u8>>,

    /// BASE64URL(JWE Ciphertext)
    pub ciphertext: Base64Binary<Vec<u8>>,

    /// BASE64URL(JWE Authentication Tag)
    pub tag: Base64Binary<Vec<u8>>,
}

/// Protected header for authcrypt-specific JWE.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct ProtectedHeader {
    /// Must be `application/didcomm-encrypted+json` or `didcomm-encrypted+json` for now.
    /// Something like `application/didcomm-encrypted+cbor` can be introduced in the
    /// future.
    pub typ: String,

    /// Cryptographic algorithm used to encrypt or determine the value of the CEK.
    pub alg: String,

    /// Identifies the content encryption algorithm used to perform authenticated encryption
    /// on the plaintext to produce the ciphertext and the Authentication Tag.
    pub enc: String,

    /// Sender KID as DID Url.
    /// If absent implementations MUST be able to resolve the sender kid from the `apu` header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skid: Option<String>,

    /// BASE64URL("skid" header value),
    pub apu: Base64Json<String>,

    /// BASE64URL(SHA256(CONCAT('.', SORT([recipients[0].kid, ..., recipients[n].kid])))))
    pub apv: Base64Json<String>,

    /// EPK generated once for all recipients.
    /// It MUST be of the same type and curve as all recipient keys since kdf
    /// with the sender key must be on the same curve.
    pub epk: JWK,
}

/// Recepient part of authcrypt-specific JWE
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Recepient {
    /// Per-recipient header
    /// Note it isn't serialized and not integrity protected
    pub header: PerRecipientHeader,

    /// BASE64URL(JWE Encrypted Key)
    pub encrypted_key: Base64Binary<Vec<u8>>,
}

/// Per-recipient header part of authcrypt-specific JWE
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct PerRecipientHeader {
    /// Recipient KID as DID URL
    pub kid: String,
}
