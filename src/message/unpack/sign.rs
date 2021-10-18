use askar_crypto::alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair};

use crate::{
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
    let mut buf = vec![];

    let msg = if let Ok(msg) = jws::parse(msg, &mut buf) {
        msg
    } else {
        return Ok(None);
    };

    if msg.protected.len() != 1 {
        Err(err_msg(
            ErrorKind::Malformed,
            "Wrong amount of signatures for jws",
        ))?
    }

    let alg = &msg
        .protected
        .first()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "Unexpected absence of first protected header",
            )
        })?
        .alg;

    let signer_kid = msg
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
        .key_agreements
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
            let signer_key = signer_key
                .as_ed25519()
                .context("Unable instantiate signer key")?;

            msg.verify::<Ed25519KeyPair>((signer_kid, &signer_key))
                .context("Unable verify sign envelope")?
        }
        jws::Algorithm::Es256 => {
            let signer_key = signer_key
                .as_p256()
                .context("Unable instantiate signer key")?;

            msg.verify::<P256KeyPair>((signer_kid, &signer_key))
                .context("Unable verify sign envelope")?
        }
        jws::Algorithm::Es256K => {
            let signer_key = signer_key
                .as_k256()
                .context("Unable instantiate signer key")?;

            msg.verify::<K256KeyPair>((signer_kid, &signer_key))
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
    let payload = base64::decode_config(msg.jws.payload, base64::URL_SAFE_NO_PAD)
        .kind(ErrorKind::Malformed, "Signed payloa is invalid base64")?;

    let payload =
        String::from_utf8(payload).kind(ErrorKind::Malformed, "Signed payload is invalid utf8")?;

    metadata.non_repudiation = true;
    metadata.sign_from = Some(signer_kid.into());

    Ok(Some(payload))
}
