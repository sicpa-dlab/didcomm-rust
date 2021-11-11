use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    jws::{self, Algorithm},
    message::from_prior::JWT_TYP,
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyPair},
        did::did_or_url,
    },
    FromPrior,
};

impl FromPrior {
    pub async fn pack<'dr, 'sr>(
        &self,
        issuer_kid: Option<&str>,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    ) -> Result<(String, String)> {
        let from_prior_str = serde_json::to_string(self)
            .kind(ErrorKind::InvalidState, "Unable serialize message")?;

        let did_doc = did_resolver
            .resolve(&self.iss)
            .await
            .context("Unable to resolve from_prior issuer DID")?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDNotResolved,
                    "from_prior issuer DIDDoc is not found",
                )
            })?;

        let authentication_kids: Vec<&str> = if let Some(issuer_kid) = issuer_kid {
            let (did, kid_opt) = did_or_url(issuer_kid);

            let kid = kid_opt.ok_or_else(|| {
                err_msg(ErrorKind::Malformed, "issuer_kid content is not DID URL")
            })?;

            if did != &self.iss {
                Err(err_msg(
                    ErrorKind::Malformed,
                    "Provided issuer_kid does not belong to from_prior.iss DID",
                ))?
            }

            let kid = did_doc
                .authentications
                .iter()
                .find(|a| *a == kid)
                .ok_or_else(|| {
                    err_msg(
                        ErrorKind::DIDUrlNotFound,
                        "Provided issuer_kid is not found in DIDDoc",
                    )
                })?;

            vec![kid]
        } else {
            did_doc.authentications.iter().map(|s| s.as_str()).collect()
        };

        let kid = *secrets_resolver
            .find_secrets(&authentication_kids)
            .await
            .context("Unable to find secrets")?
            .get(0)
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::SecretNotFound,
                    "No from_prior issuer secrets found",
                )
            })?;

        let secret = secrets_resolver
            .get_secret(kid)
            .await
            .context("Unable to find secret")?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::SecretNotFound,
                    "from_prior issuer secret not found",
                )
            })?;

        let sign_key = secret
            .as_key_pair()
            .context("Unable to instantiate from_prior issuer key")?;

        let from_prior_jwt = match sign_key {
            KnownKeyPair::Ed25519(ref key) => jws::sign_compact(
                from_prior_str.as_bytes(),
                (kid, key),
                JWT_TYP,
                Algorithm::EdDSA,
            ),
            KnownKeyPair::P256(ref key) => jws::sign_compact(
                from_prior_str.as_bytes(),
                (kid, key),
                JWT_TYP,
                Algorithm::Es256,
            ),
            KnownKeyPair::K256(ref key) => jws::sign_compact(
                from_prior_str.as_bytes(),
                (kid, key),
                JWT_TYP,
                Algorithm::Es256K,
            ),
            _ => Err(err_msg(ErrorKind::Unsupported, "Unsupported signature alg"))?,
        }
        .context("Unable to produce signature")?;

        Ok((from_prior_jwt, String::from(kid)))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        did::resolvers::ExampleDIDResolver,
        error::ErrorKind,
        secrets::resolvers::ExampleSecretsResolver,
        test_vectors::{
            ALICE_DID_DOC, CHARLIE_DID, CHARLIE_DID_DOC, CHARLIE_ROTATED_TO_ALICE_SECRETS,
            CHARLIE_SECRET_AUTH_KEY_ED25519, FROM_PRIOR_FULL, FROM_PRIOR_INVALID_EQUAL_ISS_AND_SUB,
            FROM_PRIOR_INVALID_ISS, FROM_PRIOR_INVALID_SUB, FROM_PRIOR_MINIMAL,
        },
        utils::did::did_or_url,
        FromPrior,
    };

    #[tokio::test]
    async fn from_prior_pack_works_with_issuer_kid() {
        _from_prior_pack_works_with_issuer_kid(&FROM_PRIOR_MINIMAL).await;
        _from_prior_pack_works_with_issuer_kid(&FROM_PRIOR_FULL).await;

        async fn _from_prior_pack_works_with_issuer_kid(from_prior: &FromPrior) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);
            let charlie_rotated_to_alice_secrets_resolver =
                ExampleSecretsResolver::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());

            let (from_prior_jwt, pack_kid) = from_prior
                .pack(
                    Some(&CHARLIE_SECRET_AUTH_KEY_ED25519.id),
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                )
                .await
                .expect("Unable to pack FromPrior");

            assert_eq!(pack_kid, CHARLIE_SECRET_AUTH_KEY_ED25519.id);

            let (unpacked_from_prior, unpack_kid) =
                FromPrior::unpack(&from_prior_jwt, &did_resolver)
                    .await
                    .expect("Unable to unpack FromPrior JWT");

            assert_eq!(&unpacked_from_prior, from_prior);
            assert_eq!(unpack_kid, CHARLIE_SECRET_AUTH_KEY_ED25519.id);
        }
    }

    #[tokio::test]
    async fn from_prior_pack_works_without_issuer_kid() {
        _from_prior_pack_works_without_issuer_kid(&FROM_PRIOR_MINIMAL).await;
        _from_prior_pack_works_without_issuer_kid(&FROM_PRIOR_FULL).await;

        async fn _from_prior_pack_works_without_issuer_kid(from_prior: &FromPrior) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);
            let charlie_rotated_to_alice_secrets_resolver =
                ExampleSecretsResolver::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());

            let (from_prior_jwt, pack_kid) = from_prior
                .pack(
                    None,
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                )
                .await
                .expect("Unable to pack FromPrior");

            let (did, kid) = did_or_url(&pack_kid);
            assert!(kid.is_some());
            assert_eq!(did, CHARLIE_DID);

            let (unpacked_from_prior, unpack_kid) =
                FromPrior::unpack(&from_prior_jwt, &did_resolver)
                    .await
                    .expect("Unable to unpack FromPrior JWT");

            assert_eq!(&unpacked_from_prior, from_prior);
            assert_eq!(unpack_kid, pack_kid);
        }
    }

    #[ignore = "Must be enabled after FromPrior validation is added"]
    #[tokio::test]
    async fn from_prior_pack_works_invalid() {
        _from_prior_pack_works_invalid(&FROM_PRIOR_INVALID_ISS).await;
        _from_prior_pack_works_invalid(&FROM_PRIOR_INVALID_SUB).await;
        _from_prior_pack_works_invalid(&FROM_PRIOR_INVALID_EQUAL_ISS_AND_SUB).await;

        async fn _from_prior_pack_works_invalid(from_prior: &FromPrior) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);
            let charlie_rotated_to_alice_secrets_resolver =
                ExampleSecretsResolver::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());

            let err = from_prior
                .pack(
                    None,
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                )
                .await
                .expect_err("res is ok");

            assert_eq!(err.kind(), ErrorKind::Malformed);
        }
    }
}
