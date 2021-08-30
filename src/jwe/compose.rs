use askar_crypto::{
    alg::aes::{A128CbcHs256, AesKey},
    buffer::SecretBytes,
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    jwk::ToJwk,
    kdf::{FromKeyDerivation, KeyExchange},
    repr::{KeyGen, ToSecretBytes},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{error::{ErrorKind, Result, ResultExt}, jwe::envelope::{
        Algorithm, EncAlgorithm, PerRecipientHeader, ProtectedHeader, Recepient, JWE,
    }, utils::crypto::{JoseKDF, KeyWrap}};

pub(crate) fn compose<CE, KDF, KE, KW>(
    plaintext: &[u8],
    alg: Algorithm,
    enc: EncAlgorithm,
    sender: Option<(&str, &KE)>, // (skid, sender key)
    recipients: &[(&str, &KE)],  // (kid, recipient key)
) -> Result<String>
where
    CE: KeyAeadInPlace + KeyGen + ToSecretBytes,
    KDF: JoseKDF<KE, KW>,
    KE: KeyExchange + KeyGen + ToJwk + ?Sized,
    KW: KeyWrap + FromKeyDerivation,
{
    let (skid, skey) = match sender {
        Some((skid, skey)) => (Some(skid), Some(skey)),
        None => (None, None),
    };

    let mut rng = crate::crypto::random::default_rng();
    let cek = CE::generate(&mut rng).kind(ErrorKind::InvalidState, "unable generate cek.")?;

    let apu = skid.map(|skid| base64::encode_config(skid, base64::URL_SAFE_NO_PAD));

    let apv = {
        let mut kids = recipients.iter().map(|r| r.0).collect::<Vec<_>>();
        kids.sort();
        let apv = Sha256::digest(kids.join(".").as_bytes());
        base64::encode_config(apv, base64::URL_SAFE_NO_PAD)
    };

    let epk = KE::generate(&mut rng).kind(ErrorKind::InvalidState, "unable generate epk.")?;

    let encrypted_keys = {
        let mut encrypted_keys: Vec<(&str, String)> = Vec::with_capacity(recipients.len());

        for (kid, key) in recipients {
            let kw = KDF::derive_key(
                &epk,
                skey,
                &key,
                apu.as_ref().map(|apu| apu.as_bytes()),
                apv.as_bytes(),
                false,
            )
            .kind(ErrorKind::InvalidState, "unable derive kw.")?;

            let encrypted_key = kw
                .wrap_key(&cek)
                .kind(ErrorKind::InvalidState, "unable wrap key.")?;

            let encrypted_key = base64::encode_config(&encrypted_key, base64::URL_SAFE_NO_PAD);
            encrypted_keys.push((kid.clone(), encrypted_key));
        }

        encrypted_keys
    };

    let recipients: Vec<_> = encrypted_keys
        .iter()
        .map(|(kid, encrypted_key)| Recepient {
            header: PerRecipientHeader { kid },
            encrypted_key: &encrypted_key,
        })
        .collect();

    let protected = {
        let epk = {
            let epk = epk
                .to_jwk_public(None)
                .kind(ErrorKind::InvalidState, "unable produce jwk for epk.")?;

            let epk: Value = serde_json::from_str(&epk)
                .kind(ErrorKind::InvalidState, "unable produce jwk for epk.")?;

            epk
        };

        let p = ProtectedHeader {
            typ: "application/didcomm-encrypted+json",
            alg,
            enc,
            skid,
            apu: apu.as_deref(),
            apv: &apv,
            epk,
        };

        let p = serde_json::to_string(&p).kind(
            ErrorKind::InvalidState,
            "unable serialize protected header.",
        )?;

        base64::encode_config(&p, base64::URL_SAFE_NO_PAD)
    };

    let (ciphertext, tag, iv) = {
        // TODO: use `rng` based version when available
        let iv = AesKey::<A128CbcHs256>::random_nonce();

        let mut buf = {
            let mut buf =
                SecretBytes::with_capacity(plaintext.len() + cek.aead_params().tag_length);

            buf.extend_from_slice(plaintext);
            buf
        };

        let ciphertext_len = cek
            .encrypt_in_place(&mut buf, &iv[..], protected.as_bytes())
            .kind(ErrorKind::InvalidState, "unable encrypt content.")?;

        let ciphertext = &buf.as_ref()[0..ciphertext_len];
        let tag = &buf.as_ref()[ciphertext_len..];

        let ciphertext = base64::encode_config(&ciphertext, base64::URL_SAFE_NO_PAD);
        let tag = base64::encode_config(&tag, base64::URL_SAFE_NO_PAD);
        let iv = base64::encode_config(&iv, base64::URL_SAFE_NO_PAD);

        (ciphertext, tag, iv)
    };

    let jwe = JWE {
        protected: &protected,
        recipients,
        iv: &iv,
        ciphertext: &ciphertext,
        tag: &tag,
    };

    let authcrypt =
        serde_json::to_string(&jwe).kind(ErrorKind::InvalidState, "unable serialize jwe.")?;

    Ok(authcrypt)
}
