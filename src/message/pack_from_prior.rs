use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    jws::{self, Algorithm},
    message::from_prior::FromPrior,
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyPair},
        did::did_or_url,
    },
};

impl FromPrior {
    pub async fn pack_from_prior<'dr, 'sr>(
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

        let authentication_kids: Vec<&str> = if let Some(v) = issuer_kid {
            let (did, kid_opt) = did_or_url(v);

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
            KnownKeyPair::Ed25519(ref key) => {
                jws::sign(from_prior_str.as_bytes(), (kid, key), Algorithm::EdDSA)
            }
            KnownKeyPair::P256(ref key) => {
                jws::sign(from_prior_str.as_bytes(), (kid, key), Algorithm::Es256)
            }
            KnownKeyPair::K256(ref key) => {
                jws::sign(from_prior_str.as_bytes(), (kid, key), Algorithm::Es256K)
            }
            _ => Err(err_msg(ErrorKind::Unsupported, "Unsupported signature alg"))?,
        }
        .context("Unable to produce signature")?;

        Ok((from_prior_jwt, String::from(kid)))
    }
}
