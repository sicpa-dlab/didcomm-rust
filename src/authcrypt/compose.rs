use askar_crypto::{
    alg::aes::{A128CbcHs256, A256Kw, AesKey},
    buffer::SecretBytes,
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    jwk::ToJwk,
    kdf::{ecdh_1pu::Ecdh1PU, FromKeyDerivation, KeyExchange},
    repr::{KeyGen, ToSecretBytes},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    authcrypt::envelope::{
        Algorithm, EncAlgorithm, PerRecipientHeader, ProtectedHeader, Recepient, JWE,
    },
    error::{ErrorKind, Result, ResultExt},
};

pub(crate) fn _compose<KE, CE, KW>(
    plaintext: &[u8],
    alg: Algorithm,
    enc: EncAlgorithm,
    sender: (&str, &KE),        // (skid, sender key)
    recepients: &[(&str, &KE)], // (kid, recipient key)
) -> Result<String>
where
    KE: KeyExchange + KeyGen + ToJwk + ?Sized,
    CE: KeyAeadInPlace + KeyGen + ToSecretBytes,
    KW: KeyWrap + FromKeyDerivation,
{
    let (skid, skey) = sender;
    let mut rng = crate::crypto::random::default_rng();
    let cek = CE::generate(&mut rng).kind(ErrorKind::InvalidState, "unable generate CEK.")?;
    let apu = base64::encode_config(skid, base64::URL_SAFE_NO_PAD);

    let apv = {
        let mut kids = recepients.into_iter().map(|r| r.0).collect::<Vec<_>>();
        kids.sort();
        let apv = Sha256::digest(kids.join("").as_bytes());
        base64::encode_config(apv, base64::URL_SAFE_NO_PAD)
    };

    let epk = KE::generate(&mut rng).kind(ErrorKind::InvalidState, "unable generate EPK.")?;

    let encrypted_keys = {
        let mut encrypted_keys: Vec<(&str, String)> = Vec::with_capacity(recepients.len());

        for (kid, key) in recepients {
            let deriviation = Ecdh1PU::new(
                &epk,
                &skey,
                &key,
                b"A256GCM",
                apu.as_bytes(),
                apv.as_bytes(),
                &[],
                false,
            );

            let kw = KW::from_key_derivation(deriviation)
                .kind(ErrorKind::InvalidState, "unable derive KW.")?;

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
                .kind(ErrorKind::InvalidState, "unable produce JWK for EPK.")?;

            let epk: Value = serde_json::from_str(&epk)
                .kind(ErrorKind::InvalidState, "unable produce JWK for EPK.")?;

            epk
        };

        let p = ProtectedHeader {
            typ: "application/didcomm-encrypted+json",
            alg,
            enc,
            skid: Some(skid),
            apu: &apu,
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

        let ciphertext = &buf.as_ref()[0..ciphertext_len - 1];
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
        serde_json::to_string(&jwe).kind(ErrorKind::InvalidState, "unable serialize JWE.")?;

    Ok(authcrypt)
}

/// Note that trait is compatible with KeyAeadInPlace that
pub(crate) trait KeyWrap: KeyAeadInPlace {
    fn wrap_key<K: KeyAeadInPlace + ToSecretBytes>(&self, key: &K) -> Result<SecretBytes> {
        let params = self.aead_params();

        let key_len = key
            .secret_bytes_length()
            .kind(ErrorKind::InvalidState, "unable get key len.")?;

        let mut encrypted_key = SecretBytes::with_capacity(key_len + params.tag_length);

        self.encrypt_in_place(&mut encrypted_key, &[], &[])
            .kind(ErrorKind::InvalidState, "unable encrypt.")?;

        Ok(encrypted_key)
    }
}

impl KeyWrap for AesKey<A256Kw> {}
