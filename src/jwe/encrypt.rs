use askar_crypto::{
    buffer::SecretBytes,
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    kdf::{FromKeyDerivation, KeyExchange},
    random,
    repr::{KeyGen, ToSecretBytes},
};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::future::Future;

use crate::{
    error::{ErrorKind, Result, ResultExt},
    jwe::envelope::{Algorithm, EncAlgorithm, PerRecipientHeader, ProtectedHeader, Recipient, JWE},
    jwk::ToJwkValue,
    utils::crypto::{JoseKDF, KeyWrap},
};

pub(crate) async fn encrypt<CE, KDF, KE, KW, FUT>(
    plaintext: &[u8],
    alg: Algorithm,
    enc: EncAlgorithm,
    sender: Option<(
        &str,
        impl Fn(KE, Option<String>, KE, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) -> FUT,
    )>, // (skid, derive func)
    recipients: &[(&str, &KE)], // (kid, recipient key)
) -> Result<String>
where
    CE: KeyAeadInPlace + KeyAeadMeta + KeyGen + ToSecretBytes,
    KDF: JoseKDF<KE, KW>,
    KE: KeyExchange + KeyGen + ToJwkValue + Clone,
    KW: KeyWrap + FromKeyDerivation,
    FUT: Future<Output = Result<KW>>,
{
    let (skid, derive_func) = match sender {
        Some((skid, f)) => (Some(skid), Some(f)),
        None => (None, None),
    };

    let mut rng = random::default_rng();
    let cek = CE::generate(&mut rng).kind(ErrorKind::InvalidState, "Unable generate cek")?;

    let apv = {
        let mut kids = recipients.iter().map(|r| r.0).collect::<Vec<_>>();
        kids.sort();
        Sha256::digest(kids.join(".").as_bytes())
    };

    let epk = KE::generate(&mut rng).kind(ErrorKind::InvalidState, "Unable generate epk")?;

    let protected = {
        let epk = epk.to_jwk_public_value()?;
        let apu = skid.map(|skid| base64::encode_config(skid, base64::URL_SAFE_NO_PAD));
        let apv = base64::encode_config(apv, base64::URL_SAFE_NO_PAD);

        let p = ProtectedHeader {
            typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
            alg: alg.clone(),
            enc,
            skid,
            apu: apu.as_deref(),
            apv: &apv,
            epk,
        };

        let p = serde_json::to_string(&p)
            .kind(ErrorKind::InvalidState, "Unable serialize protected header")?;

        base64::encode_config(&p, base64::URL_SAFE_NO_PAD)
    };

    let mut buf = {
        let mut buf = SecretBytes::with_capacity(plaintext.len() + cek.aead_params().tag_length);

        buf.extend_from_slice(plaintext);
        buf
    };

    let (ciphertext, tag, tag_raw, iv) = {
        // TODO: use `rng` based version when available
        let iv = CE::random_nonce();

        let ciphertext_len = cek
            .encrypt_in_place(&mut buf, &iv[..], protected.as_bytes())
            .kind(ErrorKind::InvalidState, "Unable encrypt content")?;

        let ciphertext = &buf.as_ref()[0..ciphertext_len];
        let tag_raw = &buf.as_ref()[ciphertext_len..];

        let ciphertext = base64::encode_config(&ciphertext, base64::URL_SAFE_NO_PAD);
        let tag = base64::encode_config(&tag_raw, base64::URL_SAFE_NO_PAD);
        let iv = base64::encode_config(&iv, base64::URL_SAFE_NO_PAD);

        (ciphertext, tag, tag_raw, iv)
    };

    let encrypted_keys = {
        let mut encrypted_keys: Vec<(&str, String)> = Vec::with_capacity(recipients.len());

        for (kid, key) in recipients {
            let kw = match derive_func {
                None => KDF::derive_key(
                    &epk,
                    None,
                    &key,
                    alg.as_str().as_bytes(),
                    skid.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]),
                    apv.as_slice(),
                    &tag_raw,
                    false,
                ),
                Some(ref derive_func) => {
                    derive_func(
                        epk.clone(),
                        skid.map(|x| x.to_string()),
                        key.clone().clone(),
                        alg.as_str().as_bytes().to_owned(),
                        skid.as_ref()
                            .map(|s| s.as_bytes())
                            .unwrap_or(&[])
                            .to_owned(),
                        apv.as_slice().to_owned(),
                        tag_raw.to_owned(),
                    )
                    .await
                }
            }
            .kind(ErrorKind::InvalidState, "Unable derive kw")?; //TODO Check this test and move to decrypt

            let encrypted_key = kw
                .wrap_key(&cek)
                .kind(ErrorKind::InvalidState, "Unable wrap key")?;

            let encrypted_key = base64::encode_config(&encrypted_key, base64::URL_SAFE_NO_PAD);
            encrypted_keys.push((kid.clone(), encrypted_key));
        }

        encrypted_keys
    };

    let recipients: Vec<_> = encrypted_keys
        .iter()
        .map(|(kid, encrypted_key)| Recipient {
            header: PerRecipientHeader { kid },
            encrypted_key: &encrypted_key,
        })
        .collect();

    let jwe = JWE {
        protected: &protected,
        recipients,
        iv: &iv,
        ciphertext: &ciphertext,
        tag: &tag,
    };

    let jwe = serde_json::to_string(&jwe).kind(ErrorKind::InvalidState, "Unable serialize jwe")?;

    Ok(jwe)
}

#[cfg(test)]
mod tests {
    use askar_crypto::{
        alg::{
            aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
            chacha20::{Chacha20Key, XC20P},
            p256::P256KeyPair,
            x25519::X25519KeyPair,
        },
        encrypt::{KeyAeadInPlace, KeyAeadMeta},
        jwk::FromJwk,
        kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, FromKeyDerivation, KeyExchange},
        repr::{KeyGen, KeyPublicBytes, KeySecretBytes, ToPublicBytes, ToSecretBytes},
    };

    use crate::error::err_msg;
    use crate::utils::DummyFuture;
    use crate::{
        error::{ErrorKind, Result},
        jwe::{
            self,
            envelope::{Algorithm, EncAlgorithm},
            test_support::*,
        },
        jwk::{FromJwkValue, ToJwkValue},
        utils::crypto::{JoseKDF, KeyWrap},
    };

    #[tokio::test]
    async fn encrypt_works() {
        _encrypt_works::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_X25519_1, ALICE_KEY_X25519_1, ALICE_PKEY_X25519_1)),
            &[(BOB_KID_X25519_1, BOB_KEY_X25519_1, BOB_PKEY_X25519_1)],
            Algorithm::Ecdh1puA256kw,
            EncAlgorithm::A256cbcHs512,
        )
        .await;

        _encrypt_works::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_X25519_1, ALICE_KEY_X25519_1, ALICE_PKEY_X25519_1)),
            &[
                (BOB_KID_X25519_1, BOB_KEY_X25519_1, BOB_PKEY_X25519_1),
                (BOB_KID_X25519_2, BOB_KEY_X25519_2, BOB_PKEY_X25519_2),
                (BOB_KID_X25519_3, BOB_KEY_X25519_3, BOB_PKEY_X25519_3),
            ],
            Algorithm::Ecdh1puA256kw,
            EncAlgorithm::A256cbcHs512,
        )
        .await;

        _encrypt_works::<AesKey<A256CbcHs512>, Ecdh1PU<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            Some((ALICE_KID_P256_1, ALICE_KEY_P256_1, ALICE_PKEY_P256_1)),
            &[(BOB_KID_P256_1, BOB_KEY_P256_1, BOB_PKEY_P256_1)],
            Algorithm::Ecdh1puA256kw,
            EncAlgorithm::A256cbcHs512,
        ).await;

        _encrypt_works::<AesKey<A256CbcHs512>, Ecdh1PU<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            Some((ALICE_KID_P256_1, ALICE_KEY_P256_1, ALICE_PKEY_P256_1)),
            &[
                (BOB_KID_P256_1, BOB_KEY_P256_1, BOB_PKEY_P256_1),
                (BOB_KID_P256_2, BOB_KEY_P256_2, BOB_PKEY_P256_2),
            ],
            Algorithm::Ecdh1puA256kw,
            EncAlgorithm::A256cbcHs512,
        ).await;

        _encrypt_works::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            &[(BOB_KID_X25519_1, BOB_KEY_X25519_1, BOB_PKEY_X25519_1)],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::A256cbcHs512,
        )
        .await;

        _encrypt_works::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            &[
                (BOB_KID_X25519_1, BOB_KEY_X25519_1, BOB_PKEY_X25519_1),
                (BOB_KID_X25519_2, BOB_KEY_X25519_2, BOB_PKEY_X25519_2),
                (BOB_KID_X25519_3, BOB_KEY_X25519_3, BOB_PKEY_X25519_3),
            ],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::A256cbcHs512,
        )
        .await;

        _encrypt_works::<AesKey<A256CbcHs512>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            &[(BOB_KID_P256_1, BOB_KEY_P256_1, BOB_PKEY_P256_1)],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::A256cbcHs512,
        ).await;

        _encrypt_works::<AesKey<A256CbcHs512>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            &[
                (BOB_KID_P256_1, BOB_KEY_P256_1, BOB_PKEY_P256_1),
                (BOB_KID_P256_2, BOB_KEY_P256_2, BOB_PKEY_P256_2),
            ],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::A256cbcHs512,
        ).await;

        _encrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, X25519KeyPair>, X25519KeyPair, AesKey<A256Kw>>(
            None,
            &[(BOB_KID_X25519_1, BOB_KEY_X25519_1, BOB_PKEY_X25519_1)],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::A256Gcm,
        ).await;

        _encrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, X25519KeyPair>, X25519KeyPair, AesKey<A256Kw>>(
            None,
            &[
                (BOB_KID_X25519_1, BOB_KEY_X25519_1, BOB_PKEY_X25519_1),
                (BOB_KID_X25519_2, BOB_KEY_X25519_2, BOB_PKEY_X25519_2),
                (BOB_KID_X25519_3, BOB_KEY_X25519_3, BOB_PKEY_X25519_3),
            ],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::A256Gcm,
        ).await;

        _encrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            &[(BOB_KID_P256_1, BOB_KEY_P256_1, BOB_PKEY_P256_1)],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::A256Gcm,
        )
        .await;

        _encrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            &[
                (BOB_KID_P256_1, BOB_KEY_P256_1, BOB_PKEY_P256_1),
                (BOB_KID_P256_2, BOB_KEY_P256_2, BOB_PKEY_P256_2),
            ],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::A256Gcm,
        )
        .await;

        _encrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            &[(BOB_KID_X25519_1, BOB_KEY_X25519_1, BOB_PKEY_X25519_1)],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::Xc20P,
        )
        .await;

        _encrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            &[
                (BOB_KID_X25519_1, BOB_KEY_X25519_1, BOB_PKEY_X25519_1),
                (BOB_KID_X25519_2, BOB_KEY_X25519_2, BOB_PKEY_X25519_2),
                (BOB_KID_X25519_3, BOB_KEY_X25519_3, BOB_PKEY_X25519_3),
            ],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::Xc20P,
        )
        .await;

        _encrypt_works::<Chacha20Key<XC20P>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            &[(BOB_KID_P256_1, BOB_KEY_P256_1, BOB_PKEY_P256_1)],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::Xc20P,
        )
        .await;

        _encrypt_works::<Chacha20Key<XC20P>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            &[
                (BOB_KID_P256_1, BOB_KEY_P256_1, BOB_PKEY_P256_1),
                (BOB_KID_P256_2, BOB_KEY_P256_2, BOB_PKEY_P256_2),
            ],
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::Xc20P,
        )
        .await;

        _encrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            &[
                (BOB_KID_P256_1, BOB_KEY_P256_1, BOB_PKEY_P256_1),
                (BOB_KID_P256_2, BOB_KEY_P256_2, BOB_PKEY_P256_2),
            ],
            Algorithm::Other("otherAlg".to_owned()),
            EncAlgorithm::A256Gcm,
        )
        .await;
        /// TODO: P-384 and P-521 support after solving https://github.com/hyperledger/aries-askar/issues/10

        async fn _encrypt_works<CE, KDF, KE, KW>(
            alice: Option<(&str, &str, &str)>,
            bob: &[(&str, &str, &str)],
            alg: Algorithm,
            enc_alg: EncAlgorithm,
        ) where
            CE: KeyAeadInPlace + KeyAeadMeta + KeyGen + ToSecretBytes + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange
                + KeyGen
                + ToJwkValue
                + FromJwkValue
                + ToPublicBytes
                + KeyPublicBytes
                + Clone,
            KW: KeyWrap + FromKeyDerivation,
        {
            let alice = alice.map(|a| {
                (
                    a.0,
                    KE::from_jwk(a.1).expect("Unable from_jwk"),
                    KE::from_jwk(a.2).expect("Unable from_jwk"),
                )
            });

            let alice_kid = alice.as_ref().map(|a| a.0);
            let alice_priv = alice.as_ref().map(|a| (a.0, &a.1));
            let alice_pub = alice.as_ref().map(|a| (a.0, &a.2));

            let bob = bob
                .iter()
                .map(|b| {
                    (
                        b.0,
                        KE::from_jwk(b.1).expect("Unable from_jwk"),
                        KE::from_jwk(b.2).expect("Unable from_jwk"),
                    )
                })
                .collect::<Vec<_>>();

            let bob_priv: Vec<_> = bob.iter().map(|b| (b.0, &b.1)).collect();
            let bob_pub: Vec<_> = bob.iter().map(|b| (b.0, &b.2)).collect();

            let plaintext = "Some plaintext.";

            let msg = jwe::encrypt::<CE, KDF, KE, KW, _>(
                plaintext.as_bytes(),
                alg.clone(),
                enc_alg.clone(),
                alice_priv.map(|(kid, key)| {
                    (
                        kid,
                        move |ephem_key: KE,
                              send_kid: Option<String>,
                              recip_key: KE,
                              alg: Vec<u8>,
                              apu: Vec<u8>,
                              apv: Vec<u8>,
                              cc_tag: Vec<u8>| {
                            async move {
                                if send_kid.map(|x| x.as_str() == kid).unwrap_or(false) {
                                    KDF::derive_key(
                                        &ephem_key,
                                        Some(&key),
                                        &recip_key,
                                        &alg,
                                        &apu,
                                        &apv,
                                        &cc_tag,
                                        false,
                                    )
                                } else {
                                    Err(err_msg(
                                        ErrorKind::InvalidState,
                                        "No sender key for requested kid",
                                    ))
                                }
                            }
                        },
                    )
                }),
                &bob_pub,
            )
            .await
            .expect("Unable encrypt");

            let mut buf = vec![];
            let msg = jwe::parse(&msg, &mut buf).expect("Unable parse");

            assert_eq!(msg.protected.alg, alg);
            assert_eq!(msg.protected.enc, enc_alg);
            assert_eq!(msg.jwe.recipients.len(), bob.len());

            assert_eq!(msg.apu.as_deref(), alice_kid.map(str::as_bytes));

            for recipient in &msg.jwe.recipients {
                let bob_edge_priv = bob_priv
                    .iter()
                    .find(|b| recipient.header.kid == b.0)
                    .expect("recipient not found.");

                let plaintext_ = msg
                    .decrypt::<CE, KDF, KE, KW, _>(
                        alice_pub,
                        (
                            bob_edge_priv.0,
                            |ephem_key: KE,
                             sender_key: Option<KE>,
                             recip_kid: &str,
                             alg: Vec<u8>,
                             apu: Vec<u8>,
                             apv: Vec<u8>,
                             cc_tag: Vec<u8>| {
                                async move {
                                    KDF::derive_key(
                                        &ephem_key,
                                        sender_key.as_ref(),
                                        &bob_edge_priv.1,
                                        &alg,
                                        &apu,
                                        &apv,
                                        &cc_tag,
                                        true,
                                    )
                                }
                            },
                        ),
                    )
                    .await
                    .expect("unable decrypt.");

                assert_eq!(plaintext_, plaintext.as_bytes());
            }
        }
    }

    #[tokio::test]
    async fn encrypt_works_no_sender() {
        let bob_kid = BOB_KID_X25519_1;
        let bob_pkey = X25519KeyPair::from_jwk(BOB_PKEY_X25519_1).expect("unable from_jwk");
        let plaintext = "Some plaintext.";

        let res = jwe::encrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            _,
        >(
            plaintext.as_bytes(),
            Algorithm::Ecdh1puA256kw,
            EncAlgorithm::A256cbcHs512,
            None::<(
                &str,
                &fn(
                    X25519KeyPair,
                    Option<String>,
                    X25519KeyPair,
                    Vec<u8>,
                    Vec<u8>,
                    Vec<u8>,
                    Vec<u8>,
                ) -> DummyFuture<Result<AesKey<A256Kw>>>,
            )>,
            &[(bob_kid, &bob_pkey)],
        )
        .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::InvalidState);
        assert_eq!(format!("{}", err), "Invalid state: Unable derive kw: Invalid state: No sender key for ecdh-1pu: No sender key for ecdh-1pu");
    }
}
