use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Kw, AesKey},
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::ecdh_es::EcdhEs,
};

use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwe,
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyPair},
        did::did_or_url,
    },
    UnpackMetadata, UnpackOptions,
};

pub(crate) async fn _try_unpack_authcrypt<'dr, 'sr>(
    msg: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    opts: &UnpackOptions,
    metadata: &mut UnpackMetadata,
) -> Result<Option<String>> {
    let mut buf = vec![];

    let msg = if let Ok(msg) = jwe::parse(msg, &mut buf) {
        msg
    } else {
        return Ok(None);
    };

    if msg.protected.alg != jwe::Algorithm::Ecdh1puA256kw {
        return Ok(None);
    }

    let msg = msg.verify_didcomm()?;

    let from_kid = std::str::from_utf8(
        msg.apu
            .as_deref()
            .ok_or_else(|| err_msg(ErrorKind::Malformed, "No apu presend for authcryot"))?,
    )
    .kind(ErrorKind::Malformed, "apu is invalid utf8")?;

    let (from_did, from_url) = did_or_url(from_kid);

    if from_url.is_none() {
        Err(err_msg(
            ErrorKind::Malformed,
            "Sender key can't be resolved to key agreement",
        ))?;
    }

    let from_ddoc = did_resolver
        .resolve(from_did)
        .await
        .kind(ErrorKind::InvalidState, "Unable resolve sender did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Sender did not found"))?;

    let from_kid = from_ddoc
        .key_agreements
        .iter()
        .find(|&k| k.as_str() == from_kid)
        .ok_or_else(|| err_msg(ErrorKind::DIDUrlNotFound, "Sender kid not found in did"))?;

    let from_key = from_ddoc
        .verification_methods
        .iter()
        .find(|&vm| &vm.id == from_kid)
        .ok_or_else(|| {
            err_msg(
                ErrorKind::DIDUrlNotFound,
                "Sender verification method not found in did",
            )
        })?
        .as_key_pair()?;

    let to_kids: Vec<_> = msg.jwe.recipients.iter().map(|r| r.header.kid).collect();

    let to_kid = to_kids
        .first()
        .map(|&k| k)
        .ok_or_else(|| err_msg(ErrorKind::Malformed, "No recepient keys found"))?;

    let (to_did, _) = did_or_url(to_kid);

    if let Some(_) = to_kids.iter().find(|k| {
        let (k_did, k_url) = did_or_url(k);
        (k_did != to_did) || (k_url.is_none())
    }) {
        Err(err_msg(
            ErrorKind::Malformed,
            "Recepient keys are outside of one did or can't be resolved to key agreement",
        ))?;
    }

    if metadata.encrypted_to_kids.is_none() {
        metadata.encrypted_to_kids = Some(to_kids.iter().map(|&k| k.to_owned()).collect());
    } else {
        // TODO: Verify that same keys used for authcrypt as for anoncrypt envelope
    }

    metadata.encrypted = true;

    let to_kids_found = secrets_resolver.find_secrets(&to_kids).await?;

    if to_kids_found.is_empty() {
        Err(err_msg(
            ErrorKind::SecretNotFound,
            "No recepient secrets found",
        ))?;
    }

    let mut payload: Option<Vec<u8>> = None;

    for to_kid in to_kids_found {
        let to_key = secrets_resolver
            .get_secret(to_kid)
            .await?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::InvalidState,
                    "Recepient secret not found after existence checking",
                )
            })?
            .as_key_pair()?;

        let _payload = match (&from_key, &to_key, &msg.protected.enc) {
                (KnownKeyPair::X25519(ref from_key), KnownKeyPair::X25519(ref to_key), jwe::EncAlgorithm::A256cbcHs512) => {
                    msg.decrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(Some((from_kid, from_key)), (to_kid, to_key))?
                },
                (KnownKeyPair::P256(ref from_key), KnownKeyPair::P256(ref to_key), jwe::EncAlgorithm::A256cbcHs512) => {
                    msg.decrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(Some((from_kid, from_key)), (to_kid, to_key))?
                },
                (KnownKeyPair::X25519(_), KnownKeyPair::P256(_), _) =>
                    Err(err_msg(
                        ErrorKind::Malformed,
                        "Incompatible sender and recepient key agreement curves",
                    ))?,
                (KnownKeyPair::P256(_), KnownKeyPair::X25519(_), _) =>
                    Err(err_msg(
                        ErrorKind::Malformed,
                        "Incompatible sender and recepient key agreement curves",
                    ))?,
                _ => Err(err_msg(
                    ErrorKind::Unsupported,
                    "Unsupported key agreement method",
                ))?,
            };

        payload = Some(_payload);

        if !opts.expect_decrypt_by_all_keys {
            break;
        }
    }

    let payload = payload.ok_or_else(|| err_msg(ErrorKind::InvalidState, "Payload is none"))?;

    let payload = String::from_utf8(payload)
        .kind(ErrorKind::Malformed, "Authcrypt payload is invalid utf8")?;

    Ok(Some(payload))
}
