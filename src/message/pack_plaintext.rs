use crate::{
    did::DIDResolver,
    error::{ErrorKind, Result, ResultExt},
    secrets::SecretsResolver,
    Message,
};

impl Message {
    /// Produces `DIDComm Plaintext Messages`
    /// https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages.
    ///
    /// A DIDComm message in its plaintext form, not packaged into any protective envelope,
    /// is known as a DIDComm plaintext message. Plaintext messages lack confidentiality and integrity
    /// guarantees, and are repudiable. They are therefore not normally transported across security boundaries.
    /// However, this may be a helpful format to inspect in debuggers, since it exposes underlying semantics,
    /// and it is the format used in this spec to give examples of headers and other internals.
    /// Depending on ambient security, plaintext may or may not be an appropriate format for DIDComm data at rest.
    ///
    /// # Returns
    /// - a DIDComm plaintext message s JSON string
    ///
    /// # Errors
    /// - InvalidState
    pub async fn pack_plaintext<'dr, 'sr>(
        &self,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &PackPlaintextOptions,
    ) -> Result<(String, PackPlaintextMetadata)> {
        let (message, from_prior_issuer_kid) = match &self.from_prior {
            Some(value) => {
                let (from_prior_jwt, from_prior_issuer_kid) = value
                    .pack_from_prior(options.from_prior_issuer_kid.as_deref(),
                                     did_resolver,
                                     secrets_resolver)
                    .await?;
                let cloned_message = self.clone();
                let message = Message {
                    from_prior: None,
                    from_prior_jwt: Some(from_prior_jwt),
                    ..cloned_message
                };
                (message, Some(from_prior_issuer_kid))
            }
            None => (self.clone(), None)
        };

        let packed_message =
            serde_json::to_string(&message)
                .kind(ErrorKind::InvalidState, "Unable to serialize message")?;

        let metadata = PackPlaintextMetadata { from_prior_issuer_kid };

        Ok((packed_message, metadata))
    }
}

/// Allow fine configuration of packing process.
#[derive(Debug, PartialEq, Eq)]
pub struct PackPlaintextOptions {
    // Identifier (DID URL) of from_prior issuer key
    pub from_prior_issuer_kid: Option<String>,
}

impl Default for PackPlaintextOptions {
    fn default() -> Self {
        PackPlaintextOptions {
            from_prior_issuer_kid: None,
        }
    }
}

/// Additional metadata about this `pack` method execution like used key identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackPlaintextMetadata {
    // Identifier (DID URL) of from_prior issuer key.
    pub from_prior_issuer_kid: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::{
        test_vectors::{
            ALICE_DID_DOC, ALICE_SECRETS,
            MESSAGE_ATTACHMENT_BASE64, MESSAGE_ATTACHMENT_JSON, MESSAGE_ATTACHMENT_LINKS,
            MESSAGE_ATTACHMENT_MULTI_1, MESSAGE_ATTACHMENT_MULTI_2, MESSAGE_MINIMAL,
            MESSAGE_SIMPLE, PLAINTEXT_MSG_ATTACHMENT_BASE64, PLAINTEXT_MSG_ATTACHMENT_JSON,
            PLAINTEXT_MSG_ATTACHMENT_LINKS, PLAINTEXT_MSG_ATTACHMENT_MULTI_1,
            PLAINTEXT_MSG_ATTACHMENT_MULTI_2, PLAINTEXT_MSG_MINIMAL, PLAINTEXT_MSG_SIMPLE,
        },
        Message,
    };
    use crate::did::resolvers::ExampleDIDResolver;
    use crate::message::pack_plaintext::PackPlaintextOptions;
    use crate::secrets::resolvers::ExampleSecretsResolver;

    #[tokio::test]
    async fn pack_plaintext_works() {
        _pack_plaintext_works(&MESSAGE_SIMPLE, PLAINTEXT_MSG_SIMPLE).await;
        _pack_plaintext_works(&MESSAGE_MINIMAL, PLAINTEXT_MSG_MINIMAL).await;

        _pack_plaintext_works(&MESSAGE_ATTACHMENT_BASE64, PLAINTEXT_MSG_ATTACHMENT_BASE64).await;

        _pack_plaintext_works(&MESSAGE_ATTACHMENT_JSON, PLAINTEXT_MSG_ATTACHMENT_JSON).await;
        _pack_plaintext_works(&MESSAGE_ATTACHMENT_LINKS, PLAINTEXT_MSG_ATTACHMENT_LINKS).await;

        _pack_plaintext_works(
            &MESSAGE_ATTACHMENT_MULTI_1,
            PLAINTEXT_MSG_ATTACHMENT_MULTI_1,
        )
        .await;

        _pack_plaintext_works(
            &MESSAGE_ATTACHMENT_MULTI_2,
            PLAINTEXT_MSG_ATTACHMENT_MULTI_2,
        )
        .await;

        async fn _pack_plaintext_works(msg: &Message, exp_msg: &str) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
            let secrets_resolver =
                ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (msg, metadata) =
                msg.pack_plaintext(
                    &did_resolver,
                    &secrets_resolver,
                    &PackPlaintextOptions::default(),
                )
                .await
                .expect("Unable pack_plaintext");

            let msg: Value = serde_json::from_str(&msg).expect("Unable from_str");
            let exp_msg: Value = serde_json::from_str(exp_msg).expect("Unable from_str");
            assert_eq!(msg, exp_msg)
        }
    }
}
