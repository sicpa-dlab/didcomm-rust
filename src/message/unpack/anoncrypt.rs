use crate::secrets::KeyOrKid;
use crate::{
    algorithms::AnonCryptAlg,
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwe::{self, envelope::JWE},
    secrets::KeyManagementService,
    utils::did::did_or_url,
    UnpackMetadata, UnpackOptions,
};
use askar_crypto::alg::{EcCurves, KeyAlg};
use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::ecdh_es::EcdhEs,
};

pub(crate) async fn _try_unpack_anoncrypt<'sr>(
    msg: &str,
    kms: &'sr (dyn KeyManagementService + 'sr),
    opts: &UnpackOptions,
    metadata: &mut UnpackMetadata,
) -> Result<Option<String>> {
    let jwe = match JWE::from_str(msg) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::Malformed => return Ok(None),
        Err(e) => Err(e)?,
    };

    let mut buf = vec![];
    let parsed_jwe = jwe.parse(&mut buf)?;

    if parsed_jwe.protected.alg != jwe::Algorithm::EcdhEsA256kw {
        return Ok(None);
    }

    let parsed_jwe = parsed_jwe.verify_didcomm()?;

    let to_kids: Vec<_> = parsed_jwe
        .jwe
        .recipients
        .iter()
        .map(|r| r.header.kid)
        .collect();

    let to_kid = to_kids
        .first()
        .map(|&k| k)
        .ok_or_else(|| err_msg(ErrorKind::Malformed, "No recipient keys found"))?;

    let (to_did, _) = did_or_url(to_kid);

    if let Some(_) = to_kids.iter().find(|k| {
        let (k_did, k_url) = did_or_url(k);
        (k_did != to_did) || (k_url.is_none())
    }) {
        Err(err_msg(
            ErrorKind::Malformed,
            "Recipient keys are outside of one did or can't be resolved to key agreement",
        ))?;
    }

    metadata.encrypted_to_kids = Some(to_kids.iter().map(|&k| k.to_owned()).collect());
    metadata.encrypted = true;
    metadata.anonymous_sender = true;

    let to_kids_found = kms.find_secrets(&to_kids).await?;

    if to_kids_found.is_empty() {
        Err(err_msg(
            ErrorKind::SecretNotFound,
            "No recipient secrets found",
        ))?;
    }

    let mut payload: Option<Vec<u8>> = None;

    for to_kid in to_kids_found {
        let to_key_alg = kms.get_key_alg(to_kid).await.kind(
            ErrorKind::InvalidState,
            "Recipient secret not found after existence checking",
        )?;

        let _payload = match (to_key_alg, &parsed_jwe.protected.enc) {
            (KeyAlg::X25519, jwe::EncAlgorithm::A256cbcHs512) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::A256cbcHs512EcdhEsA256kw);

                parsed_jwe.decrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                        _
                    >(None, (to_kid,
                             |ephem_key: X25519KeyPair,
                              _send_key: Option<X25519KeyPair>,
                              recip_kid: String,
                              alg: Vec<u8>,
                              apu: Vec<u8>,
                              apv: Vec<u8>,
                              _cc_tag: Vec<u8>| {
                        kms.derive_aes_key_using_ecdh_es(
                            KeyOrKid::X25519KeyPair(ephem_key), KeyOrKid::Kid(recip_kid), alg, apu, apv, true,
                        )
                })).await?
            }
            (KeyAlg::X25519, jwe::EncAlgorithm::Xc20P) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::Xc20pEcdhEsA256kw);

                parsed_jwe.decrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                        _
                    >(None, (to_kid, |ephem_key: X25519KeyPair,
                                      _send_key: Option<X25519KeyPair>,
                                      recip_kid: String,
                                      alg: Vec<u8>,
                                      apu: Vec<u8>,
                                      apv: Vec<u8>,
                                      _cc_tag: Vec<u8>| {
                    kms.derive_aes_key_using_ecdh_es(
                        KeyOrKid::X25519KeyPair(ephem_key), KeyOrKid::Kid(recip_kid), alg, apu, apv, true,
                    )
                })).await?
            }
            (KeyAlg::X25519, jwe::EncAlgorithm::A256Gcm) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::A256gcmEcdhEsA256kw);

                parsed_jwe.decrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                        _
                    >(None, (to_kid, |ephem_key: X25519KeyPair,
                                      _send_key: Option<X25519KeyPair>,
                                      recip_kid: String,
                                      alg: Vec<u8>,
                                      apu: Vec<u8>,
                                      apv: Vec<u8>,
                                      _cc_tag: Vec<u8>| {
                    kms.derive_aes_key_using_ecdh_es(
                        KeyOrKid::X25519KeyPair(ephem_key), KeyOrKid::Kid(recip_kid), alg, apu, apv, true,
                    )
                })).await?
            }
            // p256
            (KeyAlg::EcCurve(EcCurves::Secp256r1), jwe::EncAlgorithm::A256cbcHs512) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::A256cbcHs512EcdhEsA256kw);

                parsed_jwe.decrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                        _
                    >(None, (to_kid, |ephem_key: P256KeyPair,
                                      _send_key: Option<P256KeyPair>,
                                      recip_kid: String,
                                      alg: Vec<u8>,
                                      apu: Vec<u8>,
                                      apv: Vec<u8>,
                                      _cc_tag: Vec<u8>| {
                    kms.derive_aes_key_using_ecdh_es(
                        KeyOrKid::P256KeyPair(ephem_key), KeyOrKid::Kid(recip_kid), alg, apu, apv, true,
                    )
                })).await?
            }
            (KeyAlg::EcCurve(EcCurves::Secp256r1), jwe::EncAlgorithm::Xc20P) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::Xc20pEcdhEsA256kw);

                parsed_jwe.decrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                        _
                    >(None, (to_kid, |ephem_key: P256KeyPair,
                                      _send_key: Option<P256KeyPair>,
                                      recip_kid: String,
                                      alg: Vec<u8>,
                                      apu: Vec<u8>,
                                      apv: Vec<u8>,
                                      _cc_tag: Vec<u8>| {
                    kms.derive_aes_key_using_ecdh_es(
                        KeyOrKid::P256KeyPair(ephem_key), KeyOrKid::Kid(recip_kid), alg, apu, apv, true,
                    )
                })).await?
            }
            (KeyAlg::EcCurve(EcCurves::Secp256r1), jwe::EncAlgorithm::A256Gcm) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::A256gcmEcdhEsA256kw);

                parsed_jwe.decrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                        _
                    >(None, (to_kid, |ephem_key: P256KeyPair,
                                      _send_key: Option<P256KeyPair>,
                                      recip_kid: String,
                                      alg: Vec<u8>,
                                      apu: Vec<u8>,
                                      apv: Vec<u8>,
                                      _cc_tag: Vec<u8>| {
                    kms.derive_aes_key_using_ecdh_es(
                        KeyOrKid::P256KeyPair(ephem_key), KeyOrKid::Kid(recip_kid), alg, apu, apv, true,
                    )
                })).await?
            }
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported recipient key agreement method",
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
