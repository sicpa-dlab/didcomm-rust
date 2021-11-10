use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    jws,
    utils::{crypto::AsKnownKeyPair, did::did_or_url},
    FromPrior,
};
use askar_crypto::alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair};

impl FromPrior {
    pub async fn unpack<'dr>(
        from_prior_jwt: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
    ) -> Result<(FromPrior, String)> {
        let mut buf = vec![];
        let parsed = jws::parse_compact(from_prior_jwt, &mut buf)?;

        let typ = parsed.parsed_header.typ;
        let alg = parsed.parsed_header.alg.clone();
        let kid = parsed.parsed_header.kid;

        if typ != "JWT" {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior is malformed: typ is not JWT",
            ))?;
        }

        let (did, did_url) = did_or_url(kid);

        if did_url.is_none() {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior kid is not DID URL",
            ))?
        }

        let did_doc = did_resolver
            .resolve(did)
            .await
            .context("Unable to resolve from_prior issuer DID")?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDNotResolved,
                    "from_prior issuer DIDDoc not found",
                )
            })?;

        let kid = did_doc
            .authentications
            .iter()
            .find(|&k| k.as_str() == kid)
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDUrlNotFound,
                    "from_prior issuer kid not found in DIDDoc",
                )
            })?
            .as_str();

        let key = did_doc
            .verification_methods
            .iter()
            .find(|&vm| &vm.id == kid)
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDUrlNotFound,
                    "from_prior issuer verification method not found in DIDDoc",
                )
            })?;

        let valid = match alg {
            jws::Algorithm::EdDSA => {
                let key = key
                    .as_ed25519()
                    .context("Unable to instantiate from_prior issuer key")?;

                parsed
                    .verify::<Ed25519KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Es256 => {
                let key = key
                    .as_p256()
                    .context("Unable to instantiate from_prior issuer key")?;

                parsed
                    .verify::<P256KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Es256K => {
                let key = key
                    .as_k256()
                    .context("Unable to instantiate from_prior issuer key")?;

                parsed
                    .verify::<K256KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Other(_) => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported signature algorithm",
            ))?,
        };

        if !valid {
            Err(err_msg(ErrorKind::Malformed, "Wrong from_prior signature"))?
        }

        let payload = base64::decode_config(parsed.payload, base64::URL_SAFE_NO_PAD).kind(
            ErrorKind::Malformed,
            "from_prior payload is not a valid base64",
        )?;

        let payload = String::from_utf8(payload).kind(
            ErrorKind::Malformed,
            "Decoded from_prior payload is not a valid UTF-8",
        )?;

        let from_prior: FromPrior = serde_json::from_str(&payload)
            .kind(ErrorKind::Malformed, "Unable to parse from_prior")?;

        Ok((from_prior, kid.into()))
    }
}

#[cfg(test)]
mod tests {
    use lazy_static::__Deref;

    use crate::{
        did::resolvers::ExampleDIDResolver,
        error::ErrorKind,
        test_vectors::{
            ALICE_DID_DOC, CHARLIE_AUTH_METHOD_25519, CHARLIE_DID_DOC, FROM_PRIOR_FULL,
            FROM_PRIOR_JWT_FULL, FROM_PRIOR_JWT_INVALID, FROM_PRIOR_JWT_INVALID_SIGNATURE,
        },
        FromPrior,
    };

    #[tokio::test]
    async fn from_prior_unpack_works() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);

        let (from_prior, issuer_kid) = FromPrior::unpack(FROM_PRIOR_JWT_FULL, &did_resolver)
            .await
            .expect("unpack FromPrior failed");

        assert_eq!(&from_prior, FROM_PRIOR_FULL.deref());
        assert_eq!(issuer_kid, CHARLIE_AUTH_METHOD_25519.id);
    }

    #[tokio::test]
    async fn from_prior_unpack_works_invalid() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);

        let err = FromPrior::unpack(FROM_PRIOR_JWT_INVALID, &did_resolver)
            .await
            .expect_err("res is ok");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(
            format!("{}", err),
            "Malformed: Unable to parse compactly serialized JWS"
        );
    }

    #[tokio::test]
    async fn from_prior_unpack_works_invalid_signature() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);

        let err = FromPrior::unpack(FROM_PRIOR_JWT_INVALID_SIGNATURE, &did_resolver)
            .await
            .expect_err("res is ok");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(format!("{}", err), "Malformed: Unable to verify from_prior signature: Unable decode signature: Invalid last symbol 66, offset 85.");
    }
}
