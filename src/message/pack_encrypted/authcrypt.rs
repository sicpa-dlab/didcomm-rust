use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs},
};

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext},
    jwe,
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyAlg},
        did::did_or_url,
    },
};

pub(crate) async fn authcrypt<'dr, 'sr>(
    to: &str,
    from: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    msg: &[u8],
    enc_alg_auth: &AuthCryptAlg,
    enc_alg_anon: &AnonCryptAlg,
    protect_sender: bool,
) -> Result<(String, String, Vec<String>)> /* (msg, from_kid, to_kids) */ {
    let (to_did, to_kid) = did_or_url(to);

    // TODO: Avoid resolving of same dids multiple times
    // Now we resolve separately in authcrypt, anoncrypt and sign
    let to_ddoc = did_resolver
        .resolve(to_did)
        .await
        .context("Unable resolve recipient did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Recipient did not found"))?; //TODO test

    let (from_did, from_kid) = did_or_url(from);

    let from_ddoc = did_resolver
        .resolve(from_did)
        .await
        .context("Unable resolve sender did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Sender did not found"))?; //TODO test

    // Initial list of sender keys is all key_agreements of sender did doc
    // or filtered to keep only provided key
    let from_kids: Vec<_> = from_ddoc
        .key_agreements
        .iter()
        .filter(|kid| from_kid.map(|from_kid| kid == &from_kid).unwrap_or(true))
        .map(|s| s.as_str())
        .collect();

    if from_kids.is_empty() {
        Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "No sender key agreements found", //TODO test
        ))?
    }

    // Keep only sender keys present in the wallet
    let from_kids = secrets_resolver
        .find_secrets(&from_kids)
        .await
        .context("Unable find secrets")?; //TODO test

    if from_kids.is_empty() {
        Err(err_msg(
            ErrorKind::SecretNotFound,
            "No sender secrets found",
        ))?
    }

    // Resolve materials for sender keys
    let from_keys = from_kids
        .into_iter()
        .map(|kid| {
            from_ddoc
                .verification_methods
                .iter()
                .find(|vm| vm.id == kid)
                .ok_or_else(|| {
                    // TODO: support external keys
                    err_msg(
                        ErrorKind::Malformed,
                        format!(
                            "No verification material found for sender key agreement {}", //TODO test
                            kid
                        ),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;

    // Initial list of recipient keys is all key_agreements of recipient did doc
    // or filtered to keep only provided key
    let to_kids: Vec<_> = to_ddoc
        .key_agreements
        .iter()
        .filter(|kid| to_kid.map(|to_kid| kid == &to_kid).unwrap_or(true))
        .map(|s| s.as_str())
        .collect();

    if to_kids.is_empty() {
        Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "No recipient key agreements found", //TODO test
        ))?
    }

    // Resolve materials for recipient keys
    let to_keys = to_kids
        .into_iter()
        .map(|kid| {
            to_ddoc
                .verification_methods
                .iter()
                .find(|vm| vm.id == kid)
                .ok_or_else(|| {
                    // TODO: support external keys
                    err_msg(
                        ErrorKind::Malformed,
                        format!(
                            "No verification material found for recipient key agreement {}", //TODO test
                            kid
                        ),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;

    // Looking for first sender key that has supported crypto and intersects with recipient keys
    // by key alg
    let from_key = from_keys
        .iter()
        .filter(|key| key.key_alg() != KnownKeyAlg::Unsupported)
        .find(|from_key| {
            to_keys
                .iter()
                .find(|to_key| to_key.key_alg() == from_key.key_alg())
                .is_some()
        })
        .map(|&key| key)
        .ok_or_else(|| {
            err_msg(
                ErrorKind::NoCompatibleCrypto,
                "No common keys between sender and recipient found", //TODO test
            )
        })?;

    // Resolve secret for found sender key
    let from_priv_key = secrets_resolver
        .get_secret(&from_key.id)
        .await
        .context("Unable resolve sender secret")?
        .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Sender secret not found"))?; //TODO test

    let key_alg = from_key.key_alg();

    // Keep only recipient keys compatible with sender key
    let to_keys: Vec<_> = to_keys
        .into_iter()
        .filter(|key| key.key_alg() == key_alg)
        .collect();

    let msg = match key_alg {
        KnownKeyAlg::X25519 => {
            let _to_keys = to_keys
                .iter()
                .map(|vm| vm.as_x25519().map(|k| (&vm.id, k)))
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = _to_keys
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            let msg = match enc_alg_auth {
                AuthCryptAlg::A256cbcHs512Ecdh1puA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::Ecdh1puA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    Some((&from_key.id, &from_priv_key.as_x25519()?)),
                    &to_keys,
                )
                .context("Unable produce authcrypt envelope")?, //TODO test
            };

            if protect_sender {
                match enc_alg_anon {
                    AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::Xc20P,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256Gcm,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                }
            } else {
                msg
            }
        }
        KnownKeyAlg::P256 => {
            let _to_keys = to_keys
                .iter()
                .map(|vm| vm.as_p256().map(|k| (&vm.id, k)))
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = _to_keys
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            let msg = match enc_alg_auth {
                AuthCryptAlg::A256cbcHs512Ecdh1puA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::Ecdh1puA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    Some((&from_key.id, &from_priv_key.as_p256()?)),
                    &to_keys,
                )
                .context("Unable produce authcrypt envelope")?,
            };

            if protect_sender {
                match enc_alg_anon {
                    AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::Xc20P,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256Gcm,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                }
            } else {
                msg
            }
        }
        _ => Err(err_msg(
            ErrorKind::Unsupported,
            "Unsupported recipient key agreement method", //TODO test
        ))?,
    };

    let to_kids: Vec<_> = to_keys.into_iter().map(|vm| vm.id.clone()).collect();
    Ok((msg, from_key.id.clone(), to_kids))
}
