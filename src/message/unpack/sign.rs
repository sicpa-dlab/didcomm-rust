use askar_crypto::alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair};

use crate::jws::JWS;
use crate::{
    algorithms::SignAlg,
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    jws,
    utils::{crypto::AsKnownKeyPair, did::did_or_url},
    UnpackMetadata, UnpackOptions,
};

pub(crate) async fn _try_unapck_sign<'dr>(
    msg: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    _opts: &UnpackOptions,
    metadata: &mut UnpackMetadata,
) -> Result<Option<String>> {
    let jws_json = msg;

    let jws = match JWS::from_str(msg) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::Malformed => return Ok(None),
        Err(e) => Err(e)?,
    };

    let mut buf = vec![];
    let parsed_jws = jws.parse(&mut buf)?;

    if parsed_jws.protected.len() != 1 {
        Err(err_msg(
            ErrorKind::Malformed,
            "Wrong amount of signatures for jws",
        ))?
    }

    let alg = &parsed_jws
        .protected
        .first()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "Unexpected absence of first protected header",
            )
        })?
        .alg;

    let signer_kid = parsed_jws
        .jws
        .signatures
        .first()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "Unexpected absence of first signature",
            )
        })?
        .header
        .kid;

    let (signer_did, signer_url) = did_or_url(signer_kid);

    if signer_url.is_none() {
        Err(err_msg(
            ErrorKind::Malformed,
            "Signer key can't be resolved to key agreement",
        ))?
    }

    let signer_ddoc = did_resolver
        .resolve(signer_did)
        .await
        .context("Unable resolve signer did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Signer did not found"))?;

    let signer_kid = signer_ddoc
        .authentications
        .iter()
        .find(|&k| k.as_str() == signer_kid)
        .ok_or_else(|| err_msg(ErrorKind::DIDUrlNotFound, "Signer kid not found in did"))?
        .as_str();

    let signer_key = signer_ddoc
        .verification_methods
        .iter()
        .find(|&vm| &vm.id == signer_kid)
        .ok_or_else(|| {
            err_msg(
                ErrorKind::DIDUrlNotFound,
                "Sender verification method not found in did",
            )
        })?;

    let valid = match alg {
        jws::Algorithm::EdDSA => {
            metadata.sign_alg = Some(SignAlg::EdDSA);

            let signer_key = signer_key
                .as_ed25519()
                .context("Unable instantiate signer key")?;

            parsed_jws
                .verify::<Ed25519KeyPair>((signer_kid, &signer_key))
                .context("Unable verify sign envelope")?
        }
        jws::Algorithm::Es256 => {
            metadata.sign_alg = Some(SignAlg::ES256);

            let signer_key = signer_key
                .as_p256()
                .context("Unable instantiate signer key")?;

            parsed_jws
                .verify::<P256KeyPair>((signer_kid, &signer_key))
                .context("Unable verify sign envelope")?
        }
        jws::Algorithm::Es256K => {
            metadata.sign_alg = Some(SignAlg::ES256K);

            let signer_key = signer_key
                .as_k256()
                .context("Unable instantiate signer key")?;

            parsed_jws
                .verify::<K256KeyPair>((signer_kid, &signer_key))
                .context("Unable verify sign envelope")?
        }
        jws::Algorithm::Other(_) => Err(err_msg(
            ErrorKind::Unsupported,
            "Unsupported signature algorithm",
        ))?,
    };

    if !valid {
        Err(err_msg(ErrorKind::Malformed, "Wrong signature"))?
    }

    // TODO: More precise error conversion
    let payload = base64::decode_config(parsed_jws.jws.payload, base64::URL_SAFE_NO_PAD)
        .kind(ErrorKind::Malformed, "Signed payloa is invalid base64")?;

    let payload =
        String::from_utf8(payload).kind(ErrorKind::Malformed, "Signed payload is invalid utf8")?;

    metadata.authenticated = true;
    metadata.non_repudiation = true;
    metadata.sign_from = Some(signer_kid.into());
    metadata.signed_message = Some(jws_json.into());

    Ok(Some(payload))
}
