use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultExt},
    FromPrior, Message,
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
    /// - `Malformed` Signed `from_prior` JWT is malformed.
    /// - `DIDNotResolved` `from_prior` issuer DID not found.
    /// - `DIDUrlNotFound` `from_prior` issuer authentication verification method is not found.
    /// - `Unsupported` Crypto or method used for signing `from_prior` is unsupported.
    /// - `InvalidState` Indicates a library error.
    pub async fn pack_plaintext<'dr, 'sr>(
        &self,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
    ) -> Result<String> {
        let (from_prior, from_prior_issuer_kid) = match self.from_prior {
            Some(ref from_prior) => {
                let (from_prior, from_prior_issuer_kid) =
                    FromPrior::unpack(from_prior, did_resolver).await?;
                (Some(from_prior), Some(from_prior_issuer_kid))
            }
            None => (None, None),
        };

        self._validate_pack_plaintext(from_prior.as_ref(), from_prior_issuer_kid.as_deref())?;

        let msg = serde_json::to_string(self)
            .kind(ErrorKind::InvalidState, "Unable to serialize message")?;

        Ok(msg)
    }

    fn _validate_pack_plaintext(
        &self,
        from_prior: Option<&FromPrior>,
        from_prior_issuer_kid: Option<&str>,
    ) -> Result<()> {
        if let Some(from_prior) = from_prior {
            from_prior.validate_pack(from_prior_issuer_kid)?;

            if let Some(ref from) = self.from {
                if &from_prior.sub != from {
                    Err(err_msg(
                        ErrorKind::Malformed,
                        "from_prior `sub` value is not equal to message `from` value",
                    ))?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::{
        did::resolvers::ExampleDIDResolver,
        error::ErrorKind,
        secrets::resolvers::ExampleSecretsResolver,
        test_vectors::{
            ALICE_DID_DOC, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID_DOC,
            CHARLIE_SECRET_AUTH_KEY_ED25519, FROM_PRIOR_FULL, MESSAGE_ATTACHMENT_BASE64,
            MESSAGE_ATTACHMENT_JSON, MESSAGE_ATTACHMENT_LINKS, MESSAGE_ATTACHMENT_MULTI_1,
            MESSAGE_ATTACHMENT_MULTI_2, MESSAGE_FROM_PRIOR_FULL,
            MESSAGE_FROM_PRIOR_MISMATCHED_SUB_AND_FROM, MESSAGE_MINIMAL, MESSAGE_SIMPLE,
            PLAINTEXT_MSG_ATTACHMENT_BASE64, PLAINTEXT_MSG_ATTACHMENT_JSON,
            PLAINTEXT_MSG_ATTACHMENT_LINKS, PLAINTEXT_MSG_ATTACHMENT_MULTI_1,
            PLAINTEXT_MSG_ATTACHMENT_MULTI_2, PLAINTEXT_MSG_MINIMAL, PLAINTEXT_MSG_SIMPLE,
        },
        Message, UnpackOptions,
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

            let msg = msg
                .pack_plaintext(&did_resolver)
                .await
                .expect("Unable pack_plaintext");

            let msg: Value = serde_json::from_str(&msg).expect("Unable from_str");
            let exp_msg: Value = serde_json::from_str(exp_msg).expect("Unable from_str");
            assert_eq!(msg, exp_msg);
        }
    }

    #[tokio::test]
    async fn pack_plaintext_works_from_prior() {
        let did_resolver = ExampleDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
            CHARLIE_DID_DOC.clone(),
        ]);
        let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

        let packed_msg = MESSAGE_FROM_PRIOR_FULL
            .pack_plaintext(&did_resolver)
            .await
            .expect("Unable pack_plaintext");

        let (unpacked_msg, unpack_metadata) = Message::unpack(
            &packed_msg,
            &did_resolver,
            &bob_secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect("Unable unpack");

        assert_eq!(&unpacked_msg, &*MESSAGE_FROM_PRIOR_FULL);
        assert_eq!(
            unpack_metadata.from_prior_issuer_kid.as_ref(),
            Some(&CHARLIE_SECRET_AUTH_KEY_ED25519.id)
        );
        assert_eq!(unpack_metadata.from_prior.as_ref(), Some(&*FROM_PRIOR_FULL));
    }

    #[tokio::test]
    async fn pack_plaintext_works_mismatched_from_prior_sub_and_message_from() {
        let did_resolver = ExampleDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
            CHARLIE_DID_DOC.clone(),
        ]);

        let err = MESSAGE_FROM_PRIOR_MISMATCHED_SUB_AND_FROM
            .pack_plaintext(&did_resolver)
            .await
            .expect_err("res is ok");

        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: from_prior `sub` value is not equal to message `from` value"
        );
    }
}
