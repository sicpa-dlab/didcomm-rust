use crate::did::DIDResolver;
use crate::error::{ErrorKind, Result, ResultExt};
use crate::{FromPrior, Message, UnpackMetadata};

pub(crate) async fn unpack_plaintext<'dr, 'sr>(
    msg: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    metadata: &mut UnpackMetadata,
) -> Result<Message> {
    let msg: Message =
        serde_json::from_str(msg).kind(ErrorKind::Malformed, "Unable deserialize jwm")?;

    let msg = match &msg.from_prior_jwt {
        Some(from_prior_jwt) => {
            let (from_prior, from_prior_issuer_kid) =
                FromPrior::unpack(from_prior_jwt, did_resolver).await?;
            let msg = Message {
                from_prior: Some(from_prior),
                from_prior_jwt: None,
                ..msg
            };

            metadata.from_prior_jwt = Some(from_prior_jwt.clone());
            metadata.from_prior_issuer_kid = Some(from_prior_issuer_kid);

            msg
        }

        None => msg,
    };

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use crate::did::resolvers::ExampleDIDResolver;
    use crate::{Message, UnpackOptions};
    use crate::secrets::resolvers::ExampleSecretsResolver;
    use crate::test_vectors::{
        PLAINTEXT_FROM_PRIOR, MESSAGE_FROM_PRIOR, ALICE_DID_DOC, BOB_DID_DOC, CHARLIE_DID_DOC,
        BOB_SECRETS, CHARLIE_AUTH_METHOD_25519,
    };

    #[tokio::test]
    async fn unpack_plaintext_works_from_prior() {
        let did_resolver =
            ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                BOB_DID_DOC.clone(),
                CHARLIE_DID_DOC.clone(),
            ]);
        let bob_secrets_resolver =
            ExampleSecretsResolver::new(BOB_SECRETS.clone());

        let (unpacked_msg, unpack_metadata) =
            Message::unpack(
                &PLAINTEXT_FROM_PRIOR,
                &did_resolver,
                &bob_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

        assert_eq!(&unpacked_msg, MESSAGE_FROM_PRIOR.deref());
        assert_eq!(
            unpack_metadata.from_prior_issuer_kid,
            Some(CHARLIE_AUTH_METHOD_25519.id.clone())
        );

        let parsed_packed_msg: Message = serde_json::from_str(&PLAINTEXT_FROM_PRIOR)
            .expect("Unable parse packed message");

        assert_eq!(unpack_metadata.from_prior_jwt, parsed_packed_msg.from_prior_jwt);
    }
}
