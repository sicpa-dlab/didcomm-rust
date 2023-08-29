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
use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs},
};
use tokio::runtime::Handle;

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
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Recipient did not found"))?;

    let (from_did, from_kid) = did_or_url(from);

    let from_ddoc = did_resolver
        .resolve(from_did)
        .await
        .context("Unable resolve sender did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Sender did not found"))?;

    // Initial list of sender keys is all key_agreements of sender did doc
    // or filtered to keep only provided key
    let from_kids: Vec<_> = from_ddoc
        .key_agreement
        .iter()
        .filter(|kid| from_kid.map(|from_kid| kid == &from_kid).unwrap_or(true))
        .map(|s| s.as_str())
        .collect();

    if from_kids.is_empty() {
        Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "No sender key agreements found",
        ))?
    }

    // Keep only sender keys present in the wallet
    let from_kids = secrets_resolver
        .find_secrets(&from_kids)
        .await
        .context("Unable find secrets")?;

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
                .verification_method
                .iter()
                .find(|vm| vm.id == kid)
                .ok_or_else(|| {
                    // TODO: support external keys
                    err_msg(
                        ErrorKind::Malformed,
                        format!(
                            "No verification material found for sender key agreement {}",
                            kid
                        ),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;

    // Initial list of recipient keys is all key_agreements of recipient did doc
    // or filtered to keep only provided key
    let to_kids: Vec<_> = to_ddoc
        .key_agreement
        .iter()
        .filter(|kid| to_kid.map(|to_kid| kid == &to_kid).unwrap_or(true))
        .map(|s| s.as_str())
        .collect();

    if to_kids.is_empty() {
        Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "No recipient key agreements found",
        ))?
    }

    // Resolve materials for recipient keys
    let to_keys = to_kids
        .into_iter()
        .map(|kid| {
            to_ddoc
                .verification_method
                .iter()
                .find(|vm| vm.id == kid)
                .ok_or_else(|| {
                    // TODO: support external keys
                    err_msg(
                        ErrorKind::Malformed,
                        format!(
                            "No verification material found for recipient key agreement {}",
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
                "No common keys between sender and recipient found",
            )
        })?;

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
                    Some((
                        &from_key.id,
                        |ephem_key: &X25519KeyPair,
                         send_kid: Option<&str>,
                         recip_key: &X25519KeyPair,
                         alg: &[u8],
                         apu: &[u8],
                         apv: &[u8],
                         cc_tag: &[u8]| {
                            let send_kid = send_kid.ok_or_else(|| {
                                err_msg(ErrorKind::InvalidState, "No sender key for ecdh-1pu")
                            })?;

                            Handle::current().block_on(
                                secrets_resolver.derive_aes_key_from_x25519_using_edch1pu(
                                    ephem_key, send_kid, recip_key, alg, apu, apv, cc_tag, false,
                                ),
                            )
                        },
                    )),
                    &to_keys,
                )
                .context("Unable produce authcrypt envelope")?,
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
                        None::<(
                            &str,
                            &fn(
                                &X25519KeyPair,
                                Option<&str>,
                                &X25519KeyPair,
                                &[u8],
                                &[u8],
                                &[u8],
                                &[u8],
                            ) -> Result<AesKey<A256Kw>>,
                        )>,
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
                        None::<(
                            &str,
                            &fn(
                                &X25519KeyPair,
                                Option<&str>,
                                &X25519KeyPair,
                                &[u8],
                                &[u8],
                                &[u8],
                                &[u8],
                            ) -> Result<AesKey<A256Kw>>,
                        )>,
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
                        None::<(
                            &str,
                            &fn(
                                &X25519KeyPair,
                                Option<&str>,
                                &X25519KeyPair,
                                &[u8],
                                &[u8],
                                &[u8],
                                &[u8],
                            ) -> Result<AesKey<A256Kw>>,
                        )>,
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
                    Some((
                        &from_key.id,
                        &move |ephem_key: &P256KeyPair,
                               send_kid: Option<&str>,
                               recip_key: &P256KeyPair,
                               alg: &[u8],
                               apu: &[u8],
                               apv: &[u8],
                               cc_tag: &[u8]| {
                            let send_kid = send_kid.ok_or_else(|| {
                                err_msg(ErrorKind::InvalidState, "No sender key for ecdh-1pu")
                            })?;

                            Handle::current().block_on(
                                secrets_resolver.derive_aes_key_from_p256_using_edch1pu(
                                    ephem_key, send_kid, recip_key, alg, apu, apv, cc_tag, false,
                                ),
                            )
                        },
                    )),
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
                        None::<(
                            &str,
                            &fn(
                                &P256KeyPair,
                                Option<&str>,
                                &P256KeyPair,
                                &[u8],
                                &[u8],
                                &[u8],
                                &[u8],
                            ) -> Result<AesKey<A256Kw>>,
                        )>,
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
                        None::<(
                            &str,
                            &fn(
                                &P256KeyPair,
                                Option<&str>,
                                &P256KeyPair,
                                &[u8],
                                &[u8],
                                &[u8],
                                &[u8],
                            ) -> Result<AesKey<A256Kw>>,
                        )>,
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
                        None::<(
                            &str,
                            &fn(
                                &P256KeyPair,
                                Option<&str>,
                                &P256KeyPair,
                                &[u8],
                                &[u8],
                                &[u8],
                                &[u8],
                            ) -> Result<AesKey<A256Kw>>,
                        )>,
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
            "Unsupported recipient key agreement method",
        ))?,
    };

    let to_kids: Vec<_> = to_keys.into_iter().map(|vm| vm.id.clone()).collect();
    Ok((msg, from_key.id.clone(), to_kids))
}
