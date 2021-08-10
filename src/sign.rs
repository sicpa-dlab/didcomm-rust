use crate::{did::DIDResolver, error::Result, secrets::SecretsResolver, Message};

impl Message {
    /// Signs the plaintext message.
    ///
    /// # Parameters
    /// - `sign_from` a DID or key ID the sender uses for signing
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
    ///
    /// # Returns
    /// - signed message as JSON string
    ///
    pub async fn sign<'dr, 'sr>(
        &self,
        _sign_from: &str,
        _did_resolver: &'dr (dyn DIDResolver + 'dr),
        _secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    ) -> Result<(String, SignMetadata)> {
        todo!()
    }
}

/// Additional metadata about this `sign` method execution like used key identifier.
pub struct SignMetadata {
    /// Identifier (DID URL) of sign key.
    pub sign_from_kid: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    use crate::{did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver};

    #[tokio::test]
    async fn sign_works() {
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
            .sign("did:example:1", &did_resolver, &secrets_resolver)
            .await
            .expect("sign is ok.");
    }
}
