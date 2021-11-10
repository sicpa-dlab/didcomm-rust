use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::ecdh_es::EcdhEs,
};

use crate::{
    algorithms::AnonCryptAlg,
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwe,
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyPair},
        did::did_or_url,
    },
    UnpackMetadata, UnpackOptions,
};

pub(crate) async fn _try_unpack_anoncrypt<'sr>(
    msg: &str,
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    opts: &UnpackOptions,
    metadata: &mut UnpackMetadata,
) -> Result<Option<String>> {
    if !jwe::is_jwe(msg) {
        return Ok(None);
    }

    let mut buf = vec![];
    let msg = jwe::parse(msg, &mut buf)?;

    if msg.protected.alg != jwe::Algorithm::EcdhEsA256kw {
        return Ok(None);
    }

    let msg = msg.verify_didcomm()?;

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

    metadata.encrypted_to_kids = Some(to_kids.iter().map(|&k| k.to_owned()).collect());
    metadata.encrypted = true;
    metadata.anonymous_sender = true;

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

        let _payload = match (to_key, &msg.protected.enc) {
            (KnownKeyPair::X25519(ref to_key), jwe::EncAlgorithm::A256cbcHs512) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::A256cbcHs512EcdhEsA256kw);

                msg.decrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(None, (to_kid, to_key))?
            }
            (KnownKeyPair::X25519(ref to_key), jwe::EncAlgorithm::Xc20P) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::Xc20pEcdhEsA256kw);

                msg.decrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(None, (to_kid, to_key))?
            }
            (KnownKeyPair::X25519(ref to_key), jwe::EncAlgorithm::A256Gcm) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::A256gcmEcdhEsA256kw);

                msg.decrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(None, (to_kid, to_key))?
            }
            (KnownKeyPair::P256(ref to_key), jwe::EncAlgorithm::A256cbcHs512) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::A256cbcHs512EcdhEsA256kw);

                msg.decrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(None, (to_kid, to_key))?
            }
            (KnownKeyPair::P256(ref to_key), jwe::EncAlgorithm::Xc20P) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::Xc20pEcdhEsA256kw);

                msg.decrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(None, (to_kid, to_key))?
            }
            (KnownKeyPair::P256(ref to_key), jwe::EncAlgorithm::A256Gcm) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::A256gcmEcdhEsA256kw);

                msg.decrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(None, (to_kid, to_key))?
            }
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported recepient key agreement method",
            ))?,
        };

        payload = Some(_payload);

        if !opts.expect_decrypt_by_all_keys {
            break;
        }
    }

    let payload = payload.ok_or_else(|| err_msg(ErrorKind::InvalidState, "Payload is none"))?;

    let payload = String::from_utf8(payload)
        .kind(ErrorKind::Malformed, "Anoncrypt payload is invalid utf8")?;

    Ok(Some(payload))
}
