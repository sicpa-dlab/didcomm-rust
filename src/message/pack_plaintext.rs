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
        let (msg, from_prior_issuer_kid) = match &self.from_prior {
            Some(from_prior) => {
                let (from_prior_jwt, from_prior_issuer_kid) = from_prior
                    .pack(
                        options.from_prior_issuer_kid.as_deref(),
                        did_resolver,
                        secrets_resolver,
                    )
                    .await?;
                let cloned_msg = self.clone();
                let msg = Message {
                    from_prior: None,
                    from_prior_jwt: Some(from_prior_jwt),
                    ..cloned_msg
                };
                (msg, Some(from_prior_issuer_kid))
            }
            None => (self.clone(), None),
        };

        let msg = serde_json::to_string(&msg)
            .kind(ErrorKind::InvalidState, "Unable to serialize message")?;

        let metadata = PackPlaintextMetadata {
            from_prior_issuer_kid,
        };

        Ok((msg, metadata))
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
        did::resolvers::ExampleDIDResolver,
        error::ErrorKind,
        secrets::resolvers::ExampleSecretsResolver,
        test_vectors::{
            ALICE_DID_DOC, ALICE_SECRETS, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID, CHARLIE_DID_DOC,
            CHARLIE_ROTATED_TO_ALICE_SECRETS, CHARLIE_SECRET_AUTH_KEY_ED25519,
            MESSAGE_ATTACHMENT_BASE64, MESSAGE_ATTACHMENT_JSON, MESSAGE_ATTACHMENT_LINKS,
            MESSAGE_ATTACHMENT_MULTI_1, MESSAGE_ATTACHMENT_MULTI_2, MESSAGE_FROM_PRIOR,
            MESSAGE_FROM_PRIOR_FROM_PRIOR_EQUAL_ISS_AND_SUB,
            MESSAGE_FROM_PRIOR_INVALID_FROM_PRIOR_ISS, MESSAGE_FROM_PRIOR_INVALID_FROM_PRIOR_SUB,
            MESSAGE_FROM_PRIOR_MINIMAL, MESSAGE_FROM_PRIOR_MISMATCHED_FROM_PRIOR_SUB,
            MESSAGE_MINIMAL, MESSAGE_SIMPLE, PLAINTEXT_MSG_ATTACHMENT_BASE64,
            PLAINTEXT_MSG_ATTACHMENT_JSON, PLAINTEXT_MSG_ATTACHMENT_LINKS,
            PLAINTEXT_MSG_ATTACHMENT_MULTI_1, PLAINTEXT_MSG_ATTACHMENT_MULTI_2,
            PLAINTEXT_MSG_MINIMAL, PLAINTEXT_MSG_SIMPLE,
        },
        utils::did::did_or_url,
        Message, PackPlaintextMetadata, PackPlaintextOptions, UnpackOptions,
    };

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
            let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (msg, metadata) = msg
                .pack_plaintext(
                    &did_resolver,
                    &secrets_resolver,
                    &PackPlaintextOptions::default(),
                )
                .await
                .expect("Unable pack_plaintext");

            let msg: Value = serde_json::from_str(&msg).expect("Unable from_str");
            let exp_msg: Value = serde_json::from_str(exp_msg).expect("Unable from_str");
            assert_eq!(msg, exp_msg);

            let expected_metadata = PackPlaintextMetadata {
                from_prior_issuer_kid: None,
            };
            assert_eq!(metadata, expected_metadata);
        }
    }

    #[tokio::test]
    async fn pack_plaintext_works_from_prior_and_issuer_kid() {
        _pack_plaintext_works_from_prior_and_issuer_kid(&MESSAGE_FROM_PRIOR_MINIMAL).await;
        _pack_plaintext_works_from_prior_and_issuer_kid(&MESSAGE_FROM_PRIOR).await;

        async fn _pack_plaintext_works_from_prior_and_issuer_kid(msg: &Message) {
            let did_resolver = ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                BOB_DID_DOC.clone(),
                CHARLIE_DID_DOC.clone(),
            ]);
            let charlie_rotated_to_alice_secrets_resolver =
                ExampleSecretsResolver::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());
            let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

            let (packed_msg, pack_metadata) = msg
                .pack_plaintext(
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                    &PackPlaintextOptions {
                        from_prior_issuer_kid: Some(CHARLIE_SECRET_AUTH_KEY_ED25519.id.clone()),
                    },
                )
                .await
                .expect("Unable pack_plaintext");

            assert_eq!(
                pack_metadata.from_prior_issuer_kid,
                Some(CHARLIE_SECRET_AUTH_KEY_ED25519.id.clone())
            );

            let (unpacked_msg, unpack_metadata) = Message::unpack(
                &packed_msg,
                &did_resolver,
                &bob_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            assert_eq!(&unpacked_msg, msg);
            assert_eq!(
                unpack_metadata.from_prior_issuer_kid,
                Some(CHARLIE_SECRET_AUTH_KEY_ED25519.id.clone())
            );

            let parsed_packed_msg: Message =
                serde_json::from_str(&packed_msg).expect("Unable parse packed message");

            assert_eq!(
                unpack_metadata.from_prior_jwt,
                parsed_packed_msg.from_prior_jwt
            );
        }
    }

    #[tokio::test]
    async fn pack_plaintext_works_from_prior_and_no_issuer_kid() {
        _pack_plaintext_with_from_prior_works_and_no_issuer_kid(&MESSAGE_FROM_PRIOR_MINIMAL).await;
        _pack_plaintext_with_from_prior_works_and_no_issuer_kid(&MESSAGE_FROM_PRIOR).await;

        async fn _pack_plaintext_with_from_prior_works_and_no_issuer_kid(msg: &Message) {
            let did_resolver = ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                BOB_DID_DOC.clone(),
                CHARLIE_DID_DOC.clone(),
            ]);
            let charlie_rotated_to_alice_secrets_resolver =
                ExampleSecretsResolver::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());
            let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

            let (packed_msg, pack_metadata) = msg
                .pack_plaintext(
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                    &PackPlaintextOptions::default(),
                )
                .await
                .expect("Unable pack_plaintext");

            assert!(pack_metadata.from_prior_issuer_kid.is_some());

            let (did, kid) = did_or_url(pack_metadata.from_prior_issuer_kid.as_deref().unwrap());
            assert!(kid.is_some());
            assert_eq!(did, CHARLIE_DID);

            let (unpacked_msg, unpack_metadata) = Message::unpack(
                &packed_msg,
                &did_resolver,
                &bob_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            assert_eq!(&unpacked_msg, msg);
            assert_eq!(
                unpack_metadata.from_prior_issuer_kid,
                pack_metadata.from_prior_issuer_kid
            );

            let parsed_packed_msg: Message =
                serde_json::from_str(&packed_msg).expect("Unable parse packed message");

            assert_eq!(
                unpack_metadata.from_prior_jwt,
                parsed_packed_msg.from_prior_jwt
            );
        }
    }

    #[ignore = "Must be enabled after from_prior validation is added"]
    #[tokio::test]
    async fn pack_plaintext_works_invalid_from_prior() {
        _pack_plaintext_works_invalid_from_prior(&MESSAGE_FROM_PRIOR_INVALID_FROM_PRIOR_ISS).await;
        _pack_plaintext_works_invalid_from_prior(&MESSAGE_FROM_PRIOR_INVALID_FROM_PRIOR_SUB).await;
        _pack_plaintext_works_invalid_from_prior(&MESSAGE_FROM_PRIOR_FROM_PRIOR_EQUAL_ISS_AND_SUB)
            .await;
        _pack_plaintext_works_invalid_from_prior(&MESSAGE_FROM_PRIOR_MISMATCHED_FROM_PRIOR_SUB)
            .await;

        async fn _pack_plaintext_works_invalid_from_prior(msg: &Message) {
            let did_resolver = ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                BOB_DID_DOC.clone(),
                CHARLIE_DID_DOC.clone(),
            ]);
            let charlie_rotated_to_alice_secrets_resolver =
                ExampleSecretsResolver::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());

            let err = msg
                .pack_plaintext(
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                    &PackPlaintextOptions::default(),
                )
                .await
                .expect_err("res is ok");

            assert_eq!(err.kind(), ErrorKind::Malformed);
        }
    }
}
