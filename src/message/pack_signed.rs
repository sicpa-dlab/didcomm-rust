use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    jws::{self, Algorithm},
    secrets::SecretsResolver,
    utils::did::{did_or_url, ToSignKeyPair},
    Message,
};

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
        sign_by: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    ) -> Result<(String, PackSignedMetadata)> {
        let (did, key_id) = did_or_url(sign_by);

        let did_doc = did_resolver
            .resolve(did)
            .await
            .context("Unable resolve signer did")?
            .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Signer did not found"))?;

        let key_id = if let Some(key_id) = key_id {
            key_id
        } else {
            did_doc.authentications().get(0).ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDNotResolved,
                    "No authentications for signed did",
                )
            })?
        };

        let secret = secrets_resolver
            .resolve(key_id)
            .await
            .context("Unable resolve signer secret")?
            .ok_or_else(|| err_msg(ErrorKind::SecretNotFound, "Signer secret not found"))?;

        let sign_key = secret
            .to_sign_key_pair()
            .context("Unable instantiate sign key")?;

        let payload = serde_json::to_string(self)
            .kind(ErrorKind::InvalidState, "Unable serialize message")?;

        let msg = match sign_key {
            crate::utils::crypto::SignKeyPair::Ed25519KeyPair(ref key) => {
                jws::sign(payload.as_bytes(), (did, key), Algorithm::EdDSA)
            }
            crate::utils::crypto::SignKeyPair::P256KeyPair(ref key) => {
                jws::sign(payload.as_bytes(), (did, key), Algorithm::Es256)
            }
        }
        .context("Unable produce signatire")?;

        let metadata = PackSignedMetadata {
            sign_by_kid: key_id.to_owned(),
        };

        Ok((msg, metadata))
    }
}

/// Additional metadata about this `pack` method execution like used key identifiers.
pub struct PackSignedMetadata {
    /// Identifier (DID URL) of sign key.
    pub sign_by_kid: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    use crate::{did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver};

    #[tokio::test]
    #[ignore]
    // will be fixed after https://github.com/sicpa-dlab/didcomm-gemini/issues/71
    async fn pack_signed_works() {
        let msg = Message::build(
            "example-1".into(),
            "example/v1".into(),
            json!("example-body"),
        )
        .from("did:example:1".into())
        .to("did:example:2".into())
        .finalize();

        let did_resolver = ExampleDIDResolver::new(vec![]);
        let secrets_resolver = ExampleSecretsResolver::new(vec![]);

        let (_msg, _metadata) = msg
            .pack_signed("did:example:1", &did_resolver, &secrets_resolver)
            .await
            .expect("sign is ok.");
    }
}
