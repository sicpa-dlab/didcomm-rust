use askar_crypto::alg::ed25519::Ed25519KeyPair;
use askar_crypto::alg::k256::K256KeyPair;
use askar_crypto::alg::p256::P256KeyPair;
use crate::did::DIDResolver;
use crate::error::{err_msg, ErrorKind, Result, ResultContext, ResultExt};
use crate::jws;
use crate::FromPrior;
use crate::utils::crypto::AsKnownKeyPair;
use crate::utils::did::did_or_url;

impl FromPrior {
    pub async fn unpack<'dr>(
        from_prior_jwt: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
    ) -> Result<(FromPrior, String)> {
        let mut buf = vec![];
        let parsed = jws::parse_compact(from_prior_jwt, &mut buf)?;

        let typ = parsed.parsed_header.typ;
        let alg = &parsed.parsed_header.alg;
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
            .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "from_prior issuer DIDDoc not found"))?;

        let kid = did_doc
            .authentications
            .iter()
            .find(|&k| k.as_str() == kid)
            .ok_or_else(|| err_msg(ErrorKind::DIDUrlNotFound, "from_prior issuer kid not found in DIDDoc"))?
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

                parsed.verify::<Ed25519KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Es256 => {
                let key = key
                    .as_p256()
                    .context("Unable to instantiate from_prior issuer key")?;

                parsed.verify::<P256KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Es256K => {
                let key = key
                    .as_k256()
                    .context("Unable to instantiate from_prior issuer key")?;

                parsed.verify::<K256KeyPair>(&key)
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

        let from_prior: FromPrior = serde_json::from_str(parsed.payload)
            .kind(ErrorKind::Malformed, "Unable to parse from_prior")?;

        Ok((from_prior, kid.into()))
    }
}
