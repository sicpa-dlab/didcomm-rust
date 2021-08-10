use serde_json::Value;

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    did::DIDResolver,
    error::Result,
    secrets::SecretsResolver,
    Message,
};

impl Message {
    /// Packs this message to the given recipient.
    ///
    /// Encryption is done as following:
    ///  - Encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
    ///  - if `from` is None, then anonymous encryption is done (anoncrypt). 
    ///    Otherwise authenticated encryption is done (authcrypt).
    ///  - if `from` is a DID, then sender `keyAgreement` will be negotiated based on recipient preference and 
    ///    sender-recipient crypto compatibility.
    ///  - if `from` is a key ID, then the sender's `keyAgreement` verification method
    ///    identified by the given key ID is used.
    ///  - if `to` is a DID, then multiplex encryption is done for all keys from the
    ///    receiver's `keyAgreement` verification relationship
    ///    which have the same type as the sender's key.
    ///  - if `to` is a key ID, then encryption is done for the receiver's `keyAgreement`
    ///    verification method identified by the given key ID.
    ///
    /// It's possible to add non-repudiation by providing `sign_from` param in `options` (DID or key ID).
    /// 
    /// # Params
    /// - `from` a sender DID or key ID the sender uses for authenticated encryption.
    /// - `to`  a DID or key ID the sender uses for authenticated encryption.
    ///    Must match `from` header in Plaintext if the header is set.
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
    /// - `options` allow fine configuration of packing process and have implemented `Default`
    ///   that performs repudiable encryption (auth_crypt if `from` is set and anon_crypt otherwise)
    ///   and prepares a message ready to be forwarded to the message service (via `Forward` protocol).
    /// 
    /// # Returns
    /// Tuple `(packed_msg, pack_metadata)`. 
    /// - `packed_msg` packed message as a JSON string
    /// - `pack_metadata` additional metadata about this `pack` execution like used keys identifiers,
    ///   used messaging service.
    ///
    /// # Errors
    /// - DIDNotFound
    /// - SecretNotFound
    /// - NoCompatibleCrypto
    /// - InvalidState
    /// TODO: verify and update errors list
    pub async fn pack<'dr, 'sr>(
        &self,
        _from: Option<&str>,
        _to: &str,
        _did_resolver: &'dr (dyn DIDResolver + 'dr),
        _secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        _options: &PackOptions,
    ) -> Result<(String, PackMetadata)> {
        todo!("Implement me.");
    }
}

/// Allow fine configuration of packing process.
pub struct PackOptions {
    /// If `true` and message is authenticated than information about sender will be hidden from mediators, but
    /// additional re-encryption will be required. For anonymous messages this property will be ignored.
    pub hide_sender: bool,

    /// If `Some` message will be additionally signed to provide additional non-repudiable authentication
    /// by provided DID/Key.
    pub sign_from: Option<String>,

    /// Whether the packed messages need to be wrapped into `Forward` messages to be sent to Mediators
    /// as defined by the `Forward` protocol.
    pub forward: bool,

    /// if forward is enabled these optional headers can be passed to the wrapping `Forward` messages.
    /// If forward is disabled this property will be ignored.
    pub forward_headers: Option<Vec<(String, Value)>>,

    /// Identifier (DID URL) of messaging service (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
    /// If DID contains multiple messaging services it allows specify what service to use.
    /// If not present first service will be used.
    pub messaging_service: Option<String>,

    /// Algorithm used for authenticated encryption
    pub enc_alg_auth: AuthCryptAlg,

    /// Algorithm used for anonymous encryption
    pub enc_alg_anon: AnonCryptAlg,
}

impl Default for PackOptions {
    fn default() -> Self {
        PackOptions {
            hide_sender: false,
            sign_from: None,
            forward: true,
            forward_headers: None,
            messaging_service: None,
            enc_alg_auth: AuthCryptAlg::A256CBC_HS512_ECDH_1PU_A256KW,
            enc_alg_anon: AnonCryptAlg::XC20P_ECDH_ES_A256KW,
        }
    }
}

/// Additional metadata about this `pack` method execution like used keys identifiers,
/// used messaging service.
pub struct PackMetadata {
    /// Information about messaging service used for message preparation.
    /// Practically `service_endpoint` field can be used to transport the packed message.
    pub messaging_service: Option<MessagingServiceMetadata>,

    /// Identifier (DID URL) of sender key used for message encryption.
    pub from_kid: Option<String>,

    /// Identifiers (DID URLs) of recipient keys used for message encryption.
    pub to_kid: Vec<String>,
}

/// Information about messaging service used for message preparation.
/// Practically `service_endpoint` field can be used to transport the packed message.
pub struct MessagingServiceMetadata {
    /// Identifier (DID URL) of used messaging service.
    pub id: String,

    /// Service endpoint of used messaging service.
    pub service_endpoint: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    use crate::{did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver};

    #[tokio::test]
    async fn pack_works() {
        let msg = Message::build(
            "example-1".into(),
            "example/v1".into(),
            json!("example-body"),
        )
        .from("did:example:1".into())
        .to("did:example:2".into())
        .finalize();

        let did_resolver = ExampleDIDResolver::new();
        let secrets_resolver = ExampleSecretsResolver::new();

        let (_msg, _metadata) = msg
            .pack(
                Some("example-1"),
                "did:example:2",
                &did_resolver,
                &secrets_resolver,
                &PackOptions::default(),
            )
            .await
            .expect("pack is ok.");
    }
}
