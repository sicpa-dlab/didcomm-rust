use crate::{
    did::DIDResolver,
    error::{ErrorKind, Result, ResultExt},
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
    /// - InvalidState
    pub async fn pack_plaintext<'dr, 'sr>(
        &self,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
    ) -> Result<String> {
        if let Some(from_prior) = &self.from_prior {
            let (_unpacked_from_prior, _from_prior_issuer_kid) =
                FromPrior::unpack(from_prior, did_resolver).await?;

            // Add validation of FromPrior and Message fields consistency
        };

        let msg = serde_json::to_string(self)
            .kind(ErrorKind::InvalidState, "Unable to serialize message")?;

        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use lazy_static::__Deref;
    use serde_json::Value;

    use crate::{
        did::resolvers::ExampleDIDResolver,
        secrets::resolvers::ExampleSecretsResolver,
        test_vectors::{
            ALICE_DID_DOC, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID_DOC,
            CHARLIE_SECRET_AUTH_KEY_ED25519, FROM_PRIOR_FULL, MESSAGE_ATTACHMENT_BASE64,
            MESSAGE_ATTACHMENT_JSON, MESSAGE_ATTACHMENT_LINKS, MESSAGE_ATTACHMENT_MULTI_1,
            MESSAGE_ATTACHMENT_MULTI_2, MESSAGE_FROM_PRIOR_FULL, MESSAGE_MINIMAL, MESSAGE_SIMPLE,
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

        assert_eq!(&unpacked_msg, MESSAGE_FROM_PRIOR_FULL.deref());
        assert_eq!(
            unpack_metadata.from_prior_issuer_kid.as_ref(),
            Some(&CHARLIE_SECRET_AUTH_KEY_ED25519.id)
        );
        assert_eq!(
            unpack_metadata.from_prior.as_ref(),
            Some(FROM_PRIOR_FULL.deref())
        );
    }
}
