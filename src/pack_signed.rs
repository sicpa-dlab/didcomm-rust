use crate::{did::DIDResolver, error::Result, secrets::SecretsResolver, Message};

impl Message {
    /// Produces `DIDComm Signed Message`
    /// https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-message.
    ///
    /// Signed messages are not necessary to provide message integrity (tamper evidence),
    /// or to prove the sender to the recipient. Both of these guarantees automatically occur
    /// with the authenticated encryption in DIDComm encrypted messages. Signed messages are only
    /// necessary when the origin of plaintext must be provable to third parties,
    /// or when the sender can’t be proven to the recipient by authenticated encryption because
    /// the recipient is not known in advance (e.g., in a broadcast scenario).
    /// We therefore expect signed messages to be used in a few cases, but not as a matter of course.
    ///
    /// # Parameters
    /// - `sign_by` a DID or key ID the sender uses for signing
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
    ///
    /// # Returns
    /// Tuple (signed_message, metadata)
    /// - `signed_message` a DIDComm signed message as JSON string
    /// - `metadata` additional metadata about this `encrypt` execution like used keys identifiers and algorithms.
    ///
    /// # Errors
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotResolved` DID doesn't contain mentioned DID Urls (for ex., key id)
    /// - `SecretNotFound` Sender secret is not found.
    /// - `InvalidState` Indicates library error.
    /// - `IOError` IO error during DID or secrets resolving
    /// TODO: verify and update errors list
    pub async fn pack_signed<'dr, 'sr>(
        &self,
        _sign_by: &str,
        _did_resolver: &'dr (dyn DIDResolver + 'dr),
        _secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    ) -> Result<(String, SignMetadata)> {
        todo!()
    }
}

/// Additional metadata about this `pack` method execution like used key identifiers.
pub struct SignMetadata {
    /// Identifier (DID URL) of sign key.
    pub sign_by_kid: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    use crate::{did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver};

    #[tokio::test]
    async fn pack_signed_works() {
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
            .pack_signed("did:example:1", &did_resolver, &secrets_resolver)
            .await
            .expect("sign is ok.");
    }
}
