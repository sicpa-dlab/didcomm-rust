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
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext},
    jwe,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyAlg},
        did::did_or_url,
    },
};

pub(crate) async fn anoncrypt<'dr, 'sr>(
    to: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    msg: &[u8],
    enc_alg_anon: &AnonCryptAlg,
) -> Result<(String, Vec<String>)> /* (msg, to_kids) */ {
    let (to_did, to_kid) = did_or_url(to);

    // TODO: Avoid resolving of same dids multiple times
    // Now we resolve separately in authcrypt, anoncrypt and sign
    let to_ddoc = did_resolver
        .resolve(to_did)
        .await
        .context("Unable resolve recipient did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Recipient did not found"))?;

    // Initial list of recipient key ids is all key_agreements of recipient did doc
    // or one key if url was explicitly provided
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
                        ErrorKind::Unsupported,
                        "External keys are unsupported in this version",
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;

    // Looking for first supported key to determine what key alg to use
    let key_alg = to_keys
        .iter()
        .filter(|key| key.key_alg() != KnownKeyAlg::Unsupported)
        .map(|key| key.key_alg())
        .next()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "No key agreement keys found for recipient",
            )
        })?;

    // Keep only keys with determined key alg
    let to_keys: Vec<_> = to_keys
        .iter()
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

            match enc_alg_anon {
                AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    EcdhEs<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                    Chacha20Key<XC20P>,
                    EcdhEs<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::Xc20P,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256Gcm>,
                    EcdhEs<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256Gcm,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
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

            match enc_alg_anon {
                AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    EcdhEs<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                    Chacha20Key<XC20P>,
                    EcdhEs<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::Xc20P,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256Gcm>,
                    EcdhEs<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256Gcm,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
            }
        }
        _ => Err(err_msg(
            ErrorKind::InvalidState,
            "Unsupported recipient key agreement alg",
        ))?,
    };

    let to_kids: Vec<_> = to_keys.into_iter().map(|vm| vm.id.clone()).collect();
    Ok((msg, to_kids))
}
