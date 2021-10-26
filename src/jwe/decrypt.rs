use askar_crypto::{
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    kdf::{FromKeyDerivation, KeyExchange},
    repr::{KeyGen, KeySecretBytes},
};

use crate::{
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    jwe::ParsedJWE,
    jwk::{FromJwkValue, ToJwkValue},
    utils::crypto::{JoseKDF, KeyWrap},
};

impl<'a, 'b> ParsedJWE<'a, 'b> {
    pub(crate) fn decrypt<CE, KDF, KE, KW>(
        &self,
        sender: Option<(&str, &KE)>,
        recipient: (&str, &KE),
    ) -> Result<Vec<u8>>
    where
        CE: KeyAeadInPlace + KeySecretBytes,
        KDF: JoseKDF<KE, KW>,
        KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
        KW: KeyWrap + FromKeyDerivation,
    {
        let (skid, skey) = match sender {
            Some((skid, skey)) => (Some(skid), Some(skey)),
            None => (None, None),
        };

        let (kid, key) = recipient;

        if skid.map(str::as_bytes) != self.apu.as_deref() {
            Err(err_msg(ErrorKind::InvalidState, "Wrong skid used"))?
        }

        let encrypted_key = {
            let encrypted_key = self
                .jwe
                .recipients
                .iter()
                .find(|r| r.header.kid == kid)
                .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Recipient not found"))?
                .encrypted_key;

            base64::decode_config(encrypted_key, base64::URL_SAFE_NO_PAD)
                .kind(ErrorKind::Malformed, "Unable decode encrypted_key")?
        };

        let epk = KE::from_jwk_value(&self.protected.epk).context("Unable instantiate epk")?;

        let tag = base64::decode_config(self.jwe.tag, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "Unable decode tag")?;

        let kw = KDF::derive_key(
            &epk,
            skey,
            &key,
            self.protected.alg.as_str().as_bytes(),
            self.apu.as_deref().unwrap_or(&[]),
            &self.apv,
            &tag,
            true,
        )
        .kind(ErrorKind::InvalidState, "Unable derive kw")?;

        let cek: CE = kw
            .unwrap_key(&encrypted_key)
            .kind(ErrorKind::Malformed, "Unable unwrap cek")?;

        let ciphertext = base64::decode_config(self.jwe.ciphertext, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "Unable decode ciphertext")?;

        let iv = base64::decode_config(self.jwe.iv, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "Unable decode iv")?;

        let plaintext = {
            let mut buf = SecretBytes::with_capacity(ciphertext.len() + tag.len());
            buf.extend_from_slice(&ciphertext);
            buf.extend_from_slice(&tag);

            cek.decrypt_in_place(&mut buf, &iv, self.jwe.protected.as_bytes())
                .kind(ErrorKind::Malformed, "Unable decrypt content")?;

            buf.to_vec()
        };

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use askar_crypto::{
        alg::{
            aes::{A128Kw, A256CbcHs512, A256Gcm, A256Kw, AesKey},
            chacha20::{Chacha20Key, XC20P},
            p256::P256KeyPair,
            x25519::X25519KeyPair,
        },
        encrypt::KeyAeadInPlace,
        kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, FromKeyDerivation, KeyExchange},
        repr::{KeyGen, KeySecretBytes},
    };

    use crate::{
        error::{Error, ErrorKind},
        jwe::{self, test_support::*},
        jwk::{FromJwkValue, ToJwkValue},
        utils::crypto::{JoseKDF, KeyWrap},
    };

    #[test]
    fn decrypt_works() {
        // from RFC: https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04#appendix-B
        _decrypt_works::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A128Kw>,
        >(
            Some((ALICE_KID_ECDH_1PU_APP_B, ALICE_KEY_ECDH_1PU_APP_B)),
            (BOB_KID_ECDH_1PU_APP_B, BOB_KEY_ECDH_1PU_APP_B),
            MSG_ECDH_1PU_APP_B,
            PAYLOAD_ECDH_1PU_APP_B,
        );

        // from RFC: https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04#appendix-B
        _decrypt_works::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A128Kw>,
        >(
            Some((ALICE_KID_ECDH_1PU_APP_B, ALICE_KEY_ECDH_1PU_APP_B)),
            (CHARLIE_KID_ECDH_1PU_APP_B, CHARLIE_KEY_ECDH_1PU_APP_B),
            MSG_ECDH_1PU_APP_B,
            PAYLOAD_ECDH_1PU_APP_B,
        );

        _decrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_XC20P,
            PAYLOAD,
        );

        _decrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_2, BOB_KEY_X25519_2),
            MSG_ANONCRYPT_X25519_XC20P,
            PAYLOAD,
        );

        _decrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_3, BOB_KEY_X25519_3),
            MSG_ANONCRYPT_X25519_XC20P,
            PAYLOAD,
        );

        _decrypt_works::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_A256CBC,
            PAYLOAD,
        );

        _decrypt_works::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_2, BOB_KEY_X25519_2),
            MSG_ANONCRYPT_X25519_A256CBC,
            PAYLOAD,
        );

        _decrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, X25519KeyPair>, X25519KeyPair, AesKey<A256Kw>>(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_A256GSM,
            PAYLOAD,
        );

        _decrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, X25519KeyPair>, X25519KeyPair, AesKey<A256Kw>>(
            None,
            (BOB_KID_X25519_2, BOB_KEY_X25519_2),
            MSG_ANONCRYPT_X25519_A256GSM,
            PAYLOAD,
        );

        _decrypt_works::<Chacha20Key<XC20P>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_ANONCRYPT_P256_XC20P,
            PAYLOAD,
        );

        _decrypt_works::<Chacha20Key<XC20P>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            (BOB_KID_P256_2, BOB_KEY_P256_2),
            MSG_ANONCRYPT_P256_XC20P,
            PAYLOAD,
        );

        _decrypt_works::<AesKey<A256CbcHs512>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_ANONCRYPT_P256_A256CBC,
            PAYLOAD,
        );

        _decrypt_works::<AesKey<A256CbcHs512>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            (BOB_KID_P256_2, BOB_KEY_P256_2),
            MSG_ANONCRYPT_P256_A256CBC,
            PAYLOAD,
        );

        _decrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_ANONCRYPT_P256_A256GSM,
            PAYLOAD,
        );

        _decrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            None,
            (BOB_KID_P256_2, BOB_KEY_P256_2),
            MSG_ANONCRYPT_P256_A256GSM,
            PAYLOAD,
        );

        _decrypt_works::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_X25519_1, ALICE_PKEY_X25519_1)),
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_AUTHCRYPT_X25519_A256CBC,
            PAYLOAD,
        );

        _decrypt_works::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_X25519_1, ALICE_PKEY_X25519_1)),
            (BOB_KID_X25519_2, BOB_KEY_X25519_2),
            MSG_AUTHCRYPT_X25519_A256CBC,
            PAYLOAD,
        );

        _decrypt_works::<AesKey<A256CbcHs512>, Ecdh1PU<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            Some((ALICE_KID_P256_1, ALICE_PKEY_P256_1)),
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_AUTHCRYPT_P256_A256CBC,
            PAYLOAD,
        );

        _decrypt_works::<AesKey<A256CbcHs512>, Ecdh1PU<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
            Some((ALICE_KID_P256_1, ALICE_PKEY_P256_1)),
            (BOB_KID_P256_2, BOB_KEY_P256_2),
            MSG_AUTHCRYPT_P256_A256CBC,
            PAYLOAD,
        );

        /// TODO: P-384 and P-521 support after solving https://github.com/hyperledger/aries-askar/issues/10

        fn _decrypt_works<CE, KDF, KE, KW>(
            sender: Option<(&str, &str)>,
            recipient: (&str, &str),
            msg: &str,
            payload: &str,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
        {
            let res = _decrypt::<CE, KDF, KE, KW>(sender, recipient, msg);
            let res = res.expect("res is err");
            assert_eq!(res, payload.as_bytes());
        }
    }

    #[test]
    fn decrypt_works_authcrypt_different_skid() {
        let res = _decrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_X25519_1, ALICE_PKEY_P256_1)),
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_AUTHCRYPT_P256_A256CBC,
        );

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::InvalidState);
        assert_eq!(format!("{}", err), "Invalid state: Wrong skid used");
    }

    #[test]
    fn decrypt_works_authcrypt_no_skid() {
        let res = _decrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_AUTHCRYPT_P256_A256CBC,
        );

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::InvalidState);
        assert_eq!(format!("{}", err), "Invalid state: Wrong skid used");
    }

    #[test]
    fn decrypt_works_anoncrypt_skid_present() {
        let res =
            _decrypt::<AesKey<A256CbcHs512>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
                Some((ALICE_KID_P256_1, ALICE_PKEY_P256_1)),
                (BOB_KID_P256_1, BOB_KEY_P256_1),
                MSG_ANONCRYPT_P256_A256CBC,
            );

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::InvalidState);
        assert_eq!(format!("{}", err), "Invalid state: Wrong skid used");
    }

    #[test]
    fn decrypt_works_recipient_not_found() {
        let res = _decrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_P256_1, ALICE_PKEY_P256_1)),
            (BOB_KID_X25519_1, BOB_KEY_P256_1),
            MSG_AUTHCRYPT_P256_A256CBC,
        );

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::InvalidState);
        assert_eq!(format!("{}", err), "Invalid state: Recipient not found");
    }

    #[test]
    fn decrypt_works_undecodable_encrypted_key() {
        let res = _decrypt::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_XC20P_UNDECODABLE_EC,
        );

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(
            format!("{}", err),
            "Malformed: Unable decode encrypted_key: Invalid byte 33, offset 0."
        );
    }

    #[test]
    fn decrypt_works_undecodable_tag() {
        let res = _decrypt::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_XC20P_UNDECODABLE_TAG,
        );

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable decode tag: Invalid byte 33, offset 0."
        );
    }

    #[test]
    fn decrypt_works_undecodable_iv() {
        let res = _decrypt::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_XC20P_UNDECODABLE_IV,
        );

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable decode iv: Encoded text cannot have a 6-bit remainder."
        );
    }

    #[test]
    fn decrypt_works_undecodable_ciphertext() {
        let res = _decrypt::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_XC20P_UNDECODABLE_CIPHERTEXT,
        );

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable decode ciphertext: Encoded text cannot have a 6-bit remainder."
        );
    }

    #[test]
    #[ignore = "https://github.com/hyperledger/aries-askar/issues/28"]
    // There is no  key type or curve checking for FromJwk implementations in askar crypto
    // Most probably it can't open invalid curve attack vectors as invalid points should be
    // found by rust crypto, but still looks dangerous.
    fn decrypt_works_epk_different_curve() {
        let res = _decrypt::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_XC20P_EPK_DIFFERENT_CURVE,
        );

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(
            format!("{}", err),
            "Malformed: Uanble instantiate epk: Unable produce jwk"
        );
    }

    #[test]
    fn decrypt_works_epk_wrong_point() {
        let res =
            _decrypt::<Chacha20Key<XC20P>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
                None,
                (BOB_KID_P256_1, BOB_KEY_P256_1),
                MSG_ANONCRYPT_P256_XC20P_EPK_WRONG_POINT,
            );

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable instantiate epk: Unable produce jwk: Invalid key data",
        );
    }

    #[test]
    fn decrypt_works_different_recipient_key() {
        _decrypt_works_different_recipient_key::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_2),
            MSG_ANONCRYPT_X25519_XC20P,
        );

        _decrypt_works_different_recipient_key::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_2),
            MSG_ANONCRYPT_X25519_A256CBC,
        );

        _decrypt_works_different_recipient_key::<
            AesKey<A256Gcm>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_2),
            MSG_ANONCRYPT_X25519_A256GSM,
        );

        _decrypt_works_different_recipient_key::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_2),
            MSG_ANONCRYPT_P256_XC20P,
        );

        _decrypt_works_different_recipient_key::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_2),
            MSG_ANONCRYPT_P256_A256CBC,
        );

        _decrypt_works_different_recipient_key::<
            AesKey<A256Gcm>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_2),
            MSG_ANONCRYPT_P256_A256GSM,
        );

        _decrypt_works_different_recipient_key::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_X25519_1, ALICE_PKEY_X25519_1)),
            (BOB_KID_X25519_1, BOB_KEY_X25519_2),
            MSG_AUTHCRYPT_X25519_A256CBC,
        );

        _decrypt_works_different_recipient_key::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_P256_1, ALICE_PKEY_P256_1)),
            (BOB_KID_P256_1, BOB_KEY_P256_2),
            MSG_AUTHCRYPT_P256_A256CBC,
        );

        fn _decrypt_works_different_recipient_key<CE, KDF, KE, KW>(
            sender: Option<(&str, &str)>,
            recipient: (&str, &str),
            msg: &str,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
        {
            let res = _decrypt::<CE, KDF, KE, KW>(sender, recipient, msg);

            let err = res.expect_err("res is ok");
            assert_eq!(err.kind(), ErrorKind::Malformed);

            assert_eq!(
                format!("{}", err),
                "Malformed: Unable unwrap cek: Malformed: Unable decrypt key: Encryption error: Unable decrypt key: Encryption error",
            );
        }
    }

    #[test]
    fn decrypt_works_changed_enc_key() {
        _decrypt_works_changed_enc_key::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_XC20P_CHANGED_ENC_KEY,
        );

        _decrypt_works_changed_enc_key::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_A256CBC_CHANGED_ENC_KEY,
        );

        _decrypt_works_changed_enc_key::<
            AesKey<A256Gcm>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_A256GSM_CHANGED_ENC_KEY,
        );

        _decrypt_works_changed_enc_key::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_ANONCRYPT_P256_XC20P_CHANGED_ENC_KEY,
        );

        _decrypt_works_changed_enc_key::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_ANONCRYPT_P256_A256CBC_CHANGED_ENC_KEY,
        );

        _decrypt_works_changed_enc_key::<
            AesKey<A256Gcm>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_ANONCRYPT_P256_A256GSM_CHANGED_ENC_KEY,
        );

        _decrypt_works_changed_enc_key::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_X25519_1, ALICE_PKEY_X25519_1)),
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_AUTHCRYPT_X25519_A256CBC_CHANGED_ENC_KEY,
        );

        _decrypt_works_changed_enc_key::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_P256_1, ALICE_PKEY_P256_1)),
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_AUTHCRYPT_P256_A256CBC_CHANGED_ENC_KEY,
        );

        fn _decrypt_works_changed_enc_key<CE, KDF, KE, KW>(
            sender: Option<(&str, &str)>,
            recipient: (&str, &str),
            msg: &str,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
        {
            let res = _decrypt::<CE, KDF, KE, KW>(sender, recipient, msg);

            let err = res.expect_err("res is ok");
            assert_eq!(err.kind(), ErrorKind::Malformed);

            assert_eq!(
                format!("{}", err),
                "Malformed: Unable unwrap cek: Malformed: Unable decrypt key: Encryption error: Unable decrypt key: Encryption error",
            );
        }
    }

    #[test]
    fn decrypt_works_changed_second_enc_key() {
        decrypt_works_changed_second_enc_key::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_2, BOB_KEY_X25519_2),
            MSG_ANONCRYPT_X25519_XC20P_CHANGED_ENC_KEY,
            PAYLOAD,
        );

        decrypt_works_changed_second_enc_key::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_2, BOB_KEY_X25519_2),
            MSG_ANONCRYPT_X25519_A256CBC_CHANGED_ENC_KEY,
            PAYLOAD,
        );

        decrypt_works_changed_second_enc_key::<
            AesKey<A256Gcm>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_2, BOB_KEY_X25519_2),
            MSG_ANONCRYPT_X25519_A256GSM_CHANGED_ENC_KEY,
            PAYLOAD,
        );

        decrypt_works_changed_second_enc_key::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_2, BOB_KEY_P256_2),
            MSG_ANONCRYPT_P256_XC20P_CHANGED_ENC_KEY,
            PAYLOAD,
        );

        decrypt_works_changed_second_enc_key::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_2, BOB_KEY_P256_2),
            MSG_ANONCRYPT_P256_A256CBC_CHANGED_ENC_KEY,
            PAYLOAD,
        );

        decrypt_works_changed_second_enc_key::<
            AesKey<A256Gcm>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_2, BOB_KEY_P256_2),
            MSG_ANONCRYPT_P256_A256GSM_CHANGED_ENC_KEY,
            PAYLOAD,
        );

        decrypt_works_changed_second_enc_key::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_X25519_1, ALICE_PKEY_X25519_1)),
            (BOB_KID_X25519_2, BOB_KEY_X25519_2),
            MSG_AUTHCRYPT_X25519_A256CBC_CHANGED_ENC_KEY,
            PAYLOAD,
        );

        decrypt_works_changed_second_enc_key::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_P256_1, ALICE_PKEY_P256_1)),
            (BOB_KID_P256_2, BOB_KEY_P256_2),
            MSG_AUTHCRYPT_P256_A256CBC_CHANGED_ENC_KEY,
            PAYLOAD,
        );

        fn decrypt_works_changed_second_enc_key<CE, KDF, KE, KW>(
            sender: Option<(&str, &str)>,
            recipient: (&str, &str),
            msg: &str,
            payload: &str,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
        {
            let res = _decrypt::<CE, KDF, KE, KW>(sender, recipient, msg);
            let res = res.expect("res is err");
            assert_eq!(&res, payload.as_bytes());
        }
    }

    #[test]
    fn decrypt_works_changed_ciphertext() {
        _decrypt_works_changed_ciphertext::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_XC20P_CHANGED_CIPHERTEXT,
        );

        _decrypt_works_changed_ciphertext::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_A256CBC_CHANGED_CIPHERTEXT,
        );

        _decrypt_works_changed_ciphertext::<
            AesKey<A256Gcm>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_A256GSM_CHANGED_CIPHERTEXT,
        );

        _decrypt_works_changed_ciphertext::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_ANONCRYPT_P256_XC20P_CHANGED_CIPHERTEXT,
        );

        _decrypt_works_changed_ciphertext::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_ANONCRYPT_P256_A256CBC_CHANGED_CIPHERTEXT,
        );

        _decrypt_works_changed_ciphertext::<
            AesKey<A256Gcm>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_ANONCRYPT_P256_A256GSM_CHANGED_CIPHERTEXT,
        );

        _decrypt_works_changed_ciphertext::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_X25519_1, ALICE_PKEY_X25519_1)),
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_AUTHCRYPT_X25519_A256CBC_CHANGED_CIPHERTEXT,
        );

        _decrypt_works_changed_ciphertext::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_P256_1, ALICE_PKEY_P256_1)),
            (BOB_KID_P256_1, BOB_KEY_P256_1),
            MSG_AUTHCRYPT_P256_A256CBC_CHANGED_CIPHERTEXT,
        );

        fn _decrypt_works_changed_ciphertext<CE, KDF, KE, KW>(
            sender: Option<(&str, &str)>,
            recipient: (&str, &str),
            msg: &str,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
        {
            let res = _decrypt::<CE, KDF, KE, KW>(sender, recipient, msg);

            let err = res.expect_err("res is ok");
            assert_eq!(err.kind(), ErrorKind::Malformed);

            assert_eq!(
                format!("{}", err),
                "Malformed: Unable decrypt content: AEAD decryption error",
            );
        }
    }

    fn _decrypt<CE, KDF, KE, KW>(
        sender: Option<(&str, &str)>,
        recipient: (&str, &str),
        msg: &str,
    ) -> Result<Vec<u8>, Error>
    where
        CE: KeyAeadInPlace + KeySecretBytes,
        KDF: JoseKDF<KE, KW>,
        KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
        KW: KeyWrap + FromKeyDerivation,
    {
        let _sender = sender.map(|(kid, k)| (kid, KE::from_jwk(k).expect("Unable from_jwk")));
        let sender = _sender.as_ref().map(|(kid, k)| (*kid, k));

        let recipient = (
            recipient.0,
            &KE::from_jwk(recipient.1).expect("Unable from_jwk"),
        );

        let mut buf = vec![];
        let msg = jwe::parse(&msg, &mut buf).expect("Unable parse");

        msg.decrypt::<CE, KDF, KE, KW>(sender, recipient)
    }

    const PAYLOAD: &str = r#"{"id":"1234567890","typ":"application/didcomm-plain+json","type":"http://example.com/protocols/lets_do_lunch/1.0/proposal","from":"did:example:alice","to":["did:example:bob"],"created_time":1516269022,"expires_time":1516385931,"body":{"messagespecificattribute":"and its value"}}"#;

    const MSG_ANONCRYPT_X25519_XC20P: &str = r#"
    {
        "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
        "recipients":[
           {
              "encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
        "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
     }
    "#;

    const MSG_ANONCRYPT_X25519_XC20P_UNDECODABLE_EC: &str = r#"
    {
        "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
        "recipients":[
           {
              "encrypted_key":"!3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
        "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
     }
    "#;

    const MSG_ANONCRYPT_X25519_XC20P_UNDECODABLE_TAG: &str = r#"
    {
        "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
        "recipients":[
           {
              "encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"!6ylC_iAs4JvDQzXeY6MuYQ",
        "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
     }
    "#;

    const MSG_ANONCRYPT_X25519_XC20P_UNDECODABLE_IV: &str = r#"
    {
        "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
        "recipients":[
           {
              "encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
        "iv":"!ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
     }
    "#;

    const MSG_ANONCRYPT_X25519_XC20P_UNDECODABLE_CIPHERTEXT: &str = r#"
    {
        "ciphertext":"!KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
        "recipients":[
           {
              "encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
        "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
     }
    "#;

    const MSG_ANONCRYPT_X25519_XC20P_EPK_DIFFERENT_CURVE: &str = r#"
    {
        "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
        "protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJfTlRkWTQ2b1MzRm00X21JbG1XZUYyT0dTU2x1NTV1MkNJWVYyd3N0aENnIiwieSI6IkZwQnF5aVNzRHQ1bmNveVpNYW9Pci1hTE1yY01hbXRpZlNhSy1FQWtfc2sifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0=",
        "recipients":[
           {
              "encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
        "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
     }
    "#;

    const MSG_ANONCRYPT_X25519_XC20P_CHANGED_ENC_KEY: &str = r#"
    {
        "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
        "recipients":[
           {
              "encrypted_key":"2n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
        "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
     }
    "#;

    const MSG_ANONCRYPT_X25519_XC20P_CHANGED_CIPHERTEXT: &str = r#"
    {
        "ciphertext":"WWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
        "recipients":[
           {
              "encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
        "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
     }
    "#;

    const MSG_ANONCRYPT_X25519_A256CBC: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjpudWxsLCJhcHYiOiJiV3ZqdDZGM2hsUzlSeE56ZVFCQVBFOGJRdnBiQnhUa3gzS0VOUEY2aTlFIiwiZXBrIjp7ImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJ3NEpZU0dkc1BXZldkeHZSLS12R2FTTHdZX0dTRTRwVlFhUmRRMEpLU0ZJIn19",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-x25519-1"
                },
                "encrypted_key":"EPhEGPspLjEvJ_v1W5zlJGfg88huhrTEUQCfKzKXmZjp6Y7Vv9Rv0mQgb7XyeZrxKHwgMo5Vxoref9ngeT17WUuHAEEPDteF"
            },{
                "header":{
                    "kid":"did:example:bob#key-x25519-2"
                },
                "encrypted_key":"XchtfMRjcs24QNpWBk81zW74mQFR8ungyaBlpGjaOFHWf5dlCcrGvZLIT-UEY--S_UZEVknNwOOQ-lq4F5MGtkDVOpd-HoxD"
            }],
        "iv":"nzmtYMd1crLyY4rRWUAL1A",
        "ciphertext":"bDM_50XL_ArVWWgpiMZO2NFFDZqc0jFBL1RFFESE_saPogffoyDEafYFYD4OlCH9yiEOIHpZZFHrgSx66xrPrkAXfl-d3Ppin2mhx0EgiV4h8yqiN1J_dQ-b_gTsP5djIj3VxMF4mkg34oIRxuaL71DQbhWgsUw-yH16KaBHkXhQnj7T4j6lQeSrP9qNYhMD0UbXcaVzT2AvmwdhRuOuI17DrfwQMVsZnh7Zh9WwJVPwUw7pto0_YpqUacq4kq3z9ZJ1pfFEstVnRwRAosjf0UCwRzCG6nw8OJYDqS3v3_2leRsjuAk-Ro4OMt5mPki0TIBeWl8JP-5rU9kGr2o7DMUtLcNoM5NHOeKiw4BgI04lFRD-azqNXJQwlBV9Uzlq",
        "tag":"PytY0PYyjAXno1ykdMVE75LKdZA6d8yH1Ju0jZf0n8c"
    }
    "#;

    const MSG_ANONCRYPT_X25519_A256CBC_CHANGED_ENC_KEY: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjpudWxsLCJhcHYiOiJiV3ZqdDZGM2hsUzlSeE56ZVFCQVBFOGJRdnBiQnhUa3gzS0VOUEY2aTlFIiwiZXBrIjp7ImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJ3NEpZU0dkc1BXZldkeHZSLS12R2FTTHdZX0dTRTRwVlFhUmRRMEpLU0ZJIn19",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-x25519-1"
                },
                "encrypted_key":"PPhEGPspLjEvJ_v1W5zlJGfg88huhrTEUQCfKzKXmZjp6Y7Vv9Rv0mQgb7XyeZrxKHwgMo5Vxoref9ngeT17WUuHAEEPDteF"
            },{
                "header":{
                    "kid":"did:example:bob#key-x25519-2"
                },
                "encrypted_key":"XchtfMRjcs24QNpWBk81zW74mQFR8ungyaBlpGjaOFHWf5dlCcrGvZLIT-UEY--S_UZEVknNwOOQ-lq4F5MGtkDVOpd-HoxD"
            }],
        "iv":"nzmtYMd1crLyY4rRWUAL1A",
        "ciphertext":"bDM_50XL_ArVWWgpiMZO2NFFDZqc0jFBL1RFFESE_saPogffoyDEafYFYD4OlCH9yiEOIHpZZFHrgSx66xrPrkAXfl-d3Ppin2mhx0EgiV4h8yqiN1J_dQ-b_gTsP5djIj3VxMF4mkg34oIRxuaL71DQbhWgsUw-yH16KaBHkXhQnj7T4j6lQeSrP9qNYhMD0UbXcaVzT2AvmwdhRuOuI17DrfwQMVsZnh7Zh9WwJVPwUw7pto0_YpqUacq4kq3z9ZJ1pfFEstVnRwRAosjf0UCwRzCG6nw8OJYDqS3v3_2leRsjuAk-Ro4OMt5mPki0TIBeWl8JP-5rU9kGr2o7DMUtLcNoM5NHOeKiw4BgI04lFRD-azqNXJQwlBV9Uzlq",
        "tag":"PytY0PYyjAXno1ykdMVE75LKdZA6d8yH1Ju0jZf0n8c"
    }
    "#;

    const MSG_ANONCRYPT_X25519_A256CBC_CHANGED_CIPHERTEXT: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjpudWxsLCJhcHYiOiJiV3ZqdDZGM2hsUzlSeE56ZVFCQVBFOGJRdnBiQnhUa3gzS0VOUEY2aTlFIiwiZXBrIjp7ImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJ3NEpZU0dkc1BXZldkeHZSLS12R2FTTHdZX0dTRTRwVlFhUmRRMEpLU0ZJIn19",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-x25519-1"
                },
                "encrypted_key":"EPhEGPspLjEvJ_v1W5zlJGfg88huhrTEUQCfKzKXmZjp6Y7Vv9Rv0mQgb7XyeZrxKHwgMo5Vxoref9ngeT17WUuHAEEPDteF"
            },{
                "header":{
                    "kid":"did:example:bob#key-x25519-2"
                },
                "encrypted_key":"XchtfMRjcs24QNpWBk81zW74mQFR8ungyaBlpGjaOFHWf5dlCcrGvZLIT-UEY--S_UZEVknNwOOQ-lq4F5MGtkDVOpd-HoxD"
            }],
        "iv":"nzmtYMd1crLyY4rRWUAL1A",
        "ciphertext":"DDM_50XL_ArVWWgpiMZO2NFFDZqc0jFBL1RFFESE_saPogffoyDEafYFYD4OlCH9yiEOIHpZZFHrgSx66xrPrkAXfl-d3Ppin2mhx0EgiV4h8yqiN1J_dQ-b_gTsP5djIj3VxMF4mkg34oIRxuaL71DQbhWgsUw-yH16KaBHkXhQnj7T4j6lQeSrP9qNYhMD0UbXcaVzT2AvmwdhRuOuI17DrfwQMVsZnh7Zh9WwJVPwUw7pto0_YpqUacq4kq3z9ZJ1pfFEstVnRwRAosjf0UCwRzCG6nw8OJYDqS3v3_2leRsjuAk-Ro4OMt5mPki0TIBeWl8JP-5rU9kGr2o7DMUtLcNoM5NHOeKiw4BgI04lFRD-azqNXJQwlBV9Uzlq",
        "tag":"PytY0PYyjAXno1ykdMVE75LKdZA6d8yH1Ju0jZf0n8c"
    }
    "#;

    const MSG_ANONCRYPT_X25519_A256GSM: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwiYXB1IjpudWxsLCJhcHYiOiJiV3ZqdDZGM2hsUzlSeE56ZVFCQVBFOGJRdnBiQnhUa3gzS0VOUEY2aTlFIiwiZXBrIjp7ImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJQRUNaUGJMdGNPYUppTFZXa3drUW1GS1RFQmExRUVBRDZhWDIxLWR3VGlrIn19",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-x25519-1"
                },
                "encrypted_key":"jGcdRf7qopP0eNmvoNxi1pGBoaP3aO4CuJLutWTL0mudQhgzWgageQ"
            },{
                "header":{
                    "kid":"did:example:bob#key-x25519-2"
                },
                "encrypted_key":"VqW0WFtTA_UnMfSwe4cxMDSCwDr65eb8D_xqNufGD01gah8lGd9Glg"
            }],
        "iv":"o0gOvMWbBiNzkAFk",
        "ciphertext":"X357FFJqN7dW72W4q_qFSKudBtz9bkbqOfFvANVi5JgqUdVDSGFdUvJxDnPw8EkiF-DY4tYoFaONo5vOUjZniJ9R0Qg9W77pfa-J8ZgNp_lyfu5drRyGXcel95I2F5GuD3ZOGhNkeCMF2BHiOk5hQMcGsM2aJzbSnEnWjrjd0nzFAF6YGOz5UaUxUVJQOVgtzXvvcWgoU8LfGqKe5wm66Ul-PP8OmNSvLjJow0fXg9iP7qU1dwc6Qc2o_Pu80RMNUWw_A_dGaWc_lL4UbO5K7z2oPtqmDI0GTnu4LQHOcaJ3jdy-YyI_yTcnfzrFRPgHnNOhWG0OHQKywiDW5HUVu46MryOk2unqo25UMaInSubThYB3kzAQ",
        "tag":"_kECR4ioqoMVe9m42fdDcQ"
    }
    "#;

    const MSG_ANONCRYPT_X25519_A256GSM_CHANGED_ENC_KEY: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwiYXB1IjpudWxsLCJhcHYiOiJiV3ZqdDZGM2hsUzlSeE56ZVFCQVBFOGJRdnBiQnhUa3gzS0VOUEY2aTlFIiwiZXBrIjp7ImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJQRUNaUGJMdGNPYUppTFZXa3drUW1GS1RFQmExRUVBRDZhWDIxLWR3VGlrIn19",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-x25519-1"
                },
                "encrypted_key":"GGcdRf7qopP0eNmvoNxi1pGBoaP3aO4CuJLutWTL0mudQhgzWgageQ"
            },{
                "header":{
                    "kid":"did:example:bob#key-x25519-2"
                },
                "encrypted_key":"VqW0WFtTA_UnMfSwe4cxMDSCwDr65eb8D_xqNufGD01gah8lGd9Glg"
            }],
        "iv":"o0gOvMWbBiNzkAFk",
        "ciphertext":"X357FFJqN7dW72W4q_qFSKudBtz9bkbqOfFvANVi5JgqUdVDSGFdUvJxDnPw8EkiF-DY4tYoFaONo5vOUjZniJ9R0Qg9W77pfa-J8ZgNp_lyfu5drRyGXcel95I2F5GuD3ZOGhNkeCMF2BHiOk5hQMcGsM2aJzbSnEnWjrjd0nzFAF6YGOz5UaUxUVJQOVgtzXvvcWgoU8LfGqKe5wm66Ul-PP8OmNSvLjJow0fXg9iP7qU1dwc6Qc2o_Pu80RMNUWw_A_dGaWc_lL4UbO5K7z2oPtqmDI0GTnu4LQHOcaJ3jdy-YyI_yTcnfzrFRPgHnNOhWG0OHQKywiDW5HUVu46MryOk2unqo25UMaInSubThYB3kzAQ",
        "tag":"_kECR4ioqoMVe9m42fdDcQ"
    }
    "#;

    const MSG_ANONCRYPT_X25519_A256GSM_CHANGED_CIPHERTEXT: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwiYXB1IjpudWxsLCJhcHYiOiJiV3ZqdDZGM2hsUzlSeE56ZVFCQVBFOGJRdnBiQnhUa3gzS0VOUEY2aTlFIiwiZXBrIjp7ImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJQRUNaUGJMdGNPYUppTFZXa3drUW1GS1RFQmExRUVBRDZhWDIxLWR3VGlrIn19",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-x25519-1"
                },
                "encrypted_key":"jGcdRf7qopP0eNmvoNxi1pGBoaP3aO4CuJLutWTL0mudQhgzWgageQ"
            },{
                "header":{
                    "kid":"did:example:bob#key-x25519-2"
                },
                "encrypted_key":"VqW0WFtTA_UnMfSwe4cxMDSCwDr65eb8D_xqNufGD01gah8lGd9Glg"
            }],
        "iv":"o0gOvMWbBiNzkAFk",
        "ciphertext":"3357FFJqN7dW72W4q_qFSKudBtz9bkbqOfFvANVi5JgqUdVDSGFdUvJxDnPw8EkiF-DY4tYoFaONo5vOUjZniJ9R0Qg9W77pfa-J8ZgNp_lyfu5drRyGXcel95I2F5GuD3ZOGhNkeCMF2BHiOk5hQMcGsM2aJzbSnEnWjrjd0nzFAF6YGOz5UaUxUVJQOVgtzXvvcWgoU8LfGqKe5wm66Ul-PP8OmNSvLjJow0fXg9iP7qU1dwc6Qc2o_Pu80RMNUWw_A_dGaWc_lL4UbO5K7z2oPtqmDI0GTnu4LQHOcaJ3jdy-YyI_yTcnfzrFRPgHnNOhWG0OHQKywiDW5HUVu46MryOk2unqo25UMaInSubThYB3kzAQ",
        "tag":"_kECR4ioqoMVe9m42fdDcQ"
    }
    "#;

    const MSG_ANONCRYPT_P256_XC20P: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJYQzIwUCIsImFwdSI6bnVsbCwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkNVMklaXzEzZ0JhR2VxczRpUm9CclJoOVBHbzBab2lEQlFSNkdHQUJWbmciLCJ5IjoiaDJUTkh1dU5STXZNZW51TDBZcDJsU1h3dzRMNUFpc0ZKSDRXMVVzSlQ5MCJ9fQ",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-p256-1"
                }
                ,"encrypted_key":"scQxV9YQ4mQrUHgl6yAnBFDXNZAiIs_15bmoErUmoYm0HtuRclPoQg"
            },{
                "header":{
                    "kid":"did:example:bob#key-p256-2"
                },
                "encrypted_key":"CqZ-HDH2j0NC-eoUueNLKyAuMQXjQyw8bJHYM2f-lxJVm3eXCdmm2g"
            }],
        "iv":"Vg1uyuQKrU6Kw8OJK38WCpYFxW0suAP9",
        "ciphertext":"2nIm3xQcFR3HXbUPF1HS_D92OGVDvL0nIi6O5ol5tnMIa09NxJtbVAYIG7ZrkT9314PqXn_Rq77hgGE6FAOgO7aNYLyUJh0JCC_i2p_XOWuk20BYyBsmmRvVpg0DY3I1Lb-Vg1pT9pEy09gsMSLhbfqk0_TFJB1rcqzR8W0YZB5mX_53nMRf1ZatDEg4rDogSekWEGTBnlTNRua8-zoI4573SfgJ-ONt7Z_KbGO-sdRkmqXhfYNcbUyoMF9JSa-kraVuWHZP9hTz8-7R020EXfb4jodMWVOMMAiJYk1Cd7tetHXpLPdtuokaapofmtL_SNftAX2CB6ULf0axrHUNtvUyjAPvpgvSuvQuMrDlaXn16MQJ_q55",
        "tag":"etLTQvKsTvF629fykLiUDg"
    }
    "#;

    const MSG_ANONCRYPT_P256_XC20P_CHANGED_ENC_KEY: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJYQzIwUCIsImFwdSI6bnVsbCwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkNVMklaXzEzZ0JhR2VxczRpUm9CclJoOVBHbzBab2lEQlFSNkdHQUJWbmciLCJ5IjoiaDJUTkh1dU5STXZNZW51TDBZcDJsU1h3dzRMNUFpc0ZKSDRXMVVzSlQ5MCJ9fQ",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-p256-1"
                }
                ,"encrypted_key":"ccQxV9YQ4mQrUHgl6yAnBFDXNZAiIs_15bmoErUmoYm0HtuRclPoQg"
            },{
                "header":{
                    "kid":"did:example:bob#key-p256-2"
                },
                "encrypted_key":"CqZ-HDH2j0NC-eoUueNLKyAuMQXjQyw8bJHYM2f-lxJVm3eXCdmm2g"
            }],
        "iv":"Vg1uyuQKrU6Kw8OJK38WCpYFxW0suAP9",
        "ciphertext":"2nIm3xQcFR3HXbUPF1HS_D92OGVDvL0nIi6O5ol5tnMIa09NxJtbVAYIG7ZrkT9314PqXn_Rq77hgGE6FAOgO7aNYLyUJh0JCC_i2p_XOWuk20BYyBsmmRvVpg0DY3I1Lb-Vg1pT9pEy09gsMSLhbfqk0_TFJB1rcqzR8W0YZB5mX_53nMRf1ZatDEg4rDogSekWEGTBnlTNRua8-zoI4573SfgJ-ONt7Z_KbGO-sdRkmqXhfYNcbUyoMF9JSa-kraVuWHZP9hTz8-7R020EXfb4jodMWVOMMAiJYk1Cd7tetHXpLPdtuokaapofmtL_SNftAX2CB6ULf0axrHUNtvUyjAPvpgvSuvQuMrDlaXn16MQJ_q55",
        "tag":"etLTQvKsTvF629fykLiUDg"
    }
    "#;

    const MSG_ANONCRYPT_P256_XC20P_EPK_WRONG_POINT: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJYQzIwUCIsImFwdSI6bnVsbCwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkZSQW1UQmljUFZJXy1aRnF2WEJwNzZhV2pZM0gzYlpGZlhocHRUNm1ETnciLCJ5IjoiLXZ0LTFIaHRvVjBwN2xrbGIxTnRvMWRhU0lqQnV3cVZzbGIwcC1uOWRrdyJ9fQ==",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-p256-1"
                }
                ,"encrypted_key":"scQxV9YQ4mQrUHgl6yAnBFDXNZAiIs_15bmoErUmoYm0HtuRclPoQg"
            },{
                "header":{
                    "kid":"did:example:bob#key-p256-2"
                },
                "encrypted_key":"CqZ-HDH2j0NC-eoUueNLKyAuMQXjQyw8bJHYM2f-lxJVm3eXCdmm2g"
            }],
        "iv":"Vg1uyuQKrU6Kw8OJK38WCpYFxW0suAP9",
        "ciphertext":"2nIm3xQcFR3HXbUPF1HS_D92OGVDvL0nIi6O5ol5tnMIa09NxJtbVAYIG7ZrkT9314PqXn_Rq77hgGE6FAOgO7aNYLyUJh0JCC_i2p_XOWuk20BYyBsmmRvVpg0DY3I1Lb-Vg1pT9pEy09gsMSLhbfqk0_TFJB1rcqzR8W0YZB5mX_53nMRf1ZatDEg4rDogSekWEGTBnlTNRua8-zoI4573SfgJ-ONt7Z_KbGO-sdRkmqXhfYNcbUyoMF9JSa-kraVuWHZP9hTz8-7R020EXfb4jodMWVOMMAiJYk1Cd7tetHXpLPdtuokaapofmtL_SNftAX2CB6ULf0axrHUNtvUyjAPvpgvSuvQuMrDlaXn16MQJ_q55",
        "tag":"etLTQvKsTvF629fykLiUDg"
    }
    "#;

    const MSG_ANONCRYPT_P256_XC20P_CHANGED_CIPHERTEXT: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJYQzIwUCIsImFwdSI6bnVsbCwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkNVMklaXzEzZ0JhR2VxczRpUm9CclJoOVBHbzBab2lEQlFSNkdHQUJWbmciLCJ5IjoiaDJUTkh1dU5STXZNZW51TDBZcDJsU1h3dzRMNUFpc0ZKSDRXMVVzSlQ5MCJ9fQ",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-p256-1"
                }
                ,"encrypted_key":"scQxV9YQ4mQrUHgl6yAnBFDXNZAiIs_15bmoErUmoYm0HtuRclPoQg"
            },{
                "header":{
                    "kid":"did:example:bob#key-p256-2"
                },
                "encrypted_key":"CqZ-HDH2j0NC-eoUueNLKyAuMQXjQyw8bJHYM2f-lxJVm3eXCdmm2g"
            }],
        "iv":"Vg1uyuQKrU6Kw8OJK38WCpYFxW0suAP9",
        "ciphertext":"nnIm3xQcFR3HXbUPF1HS_D92OGVDvL0nIi6O5ol5tnMIa09NxJtbVAYIG7ZrkT9314PqXn_Rq77hgGE6FAOgO7aNYLyUJh0JCC_i2p_XOWuk20BYyBsmmRvVpg0DY3I1Lb-Vg1pT9pEy09gsMSLhbfqk0_TFJB1rcqzR8W0YZB5mX_53nMRf1ZatDEg4rDogSekWEGTBnlTNRua8-zoI4573SfgJ-ONt7Z_KbGO-sdRkmqXhfYNcbUyoMF9JSa-kraVuWHZP9hTz8-7R020EXfb4jodMWVOMMAiJYk1Cd7tetHXpLPdtuokaapofmtL_SNftAX2CB6ULf0axrHUNtvUyjAPvpgvSuvQuMrDlaXn16MQJ_q55",
        "tag":"etLTQvKsTvF629fykLiUDg"
    }
    "#;

    const MSG_ANONCRYPT_P256_A256CBC: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjpudWxsLCJhcHYiOiJ6LUxxcHZWWERiX3NHWW4zbWpRTHB1dTJDUUxld1l1Wm9UV09JWFBIM0ZNIiwiZXBrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiLXh2cnltSzFLNnN3R0tLZ2VERUJyQmdhSnhWSFd1R09nTU1wTWc2OFRzYyIsInkiOiJGa3hqeUdzdVlQRVZuS3lSQ1l2a3J2ejl6cno3OTFMX2dCcWtzOWc2Y2R3In19",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-p256-1"
                },
                "encrypted_key":"ReussjPSY0lT5zdj_XZgBTylAxa2yBL4Sc6rM7E42p-PsDJF60sdhAj2tm9Zg6POBI09YAy44Sygdw3rbLvcKshj6M9uD3Nc"
            },{
                "header":{
                    "kid":"did:example:bob#key-p256-2"
                },
                "encrypted_key":"s9jBWrES_9Fvnjxof3EDlDM_i3Ds3ry6pXeIOh2n8kp15L3e6CQ2yyNeEmOwuFhVwfUxuRQbM3mVlKLtySh6UtmyzSm0UZpl"
            }],
        "iv":"GIBpOTfWoimvyheRyaDlVQ",
        "ciphertext":"Dk1zcI0w1zyJjaLuaWzbOOLxsaiin1yMqHo2pI--7dJpgNID4YJCbdorekPJO5dcN8JX97DimOsZZyTde5wjZGWhRzTfHwIZT4OK9--gETjifddt2JUk0Dp72lpV35Ie6_5xU8KZEBlcajO5StBWg2sWua3hEpXTq3yJDAEMTp0Sz-CKqMlQ4frqPHJapjOz010-xVIR8cmmLoVOIA2wb5pD3uK8LLYwxUJzR-Eq5dlD6k1TtDCdZQEY38AT7a3QJ4Q49fIkZ7epREn9qLobqZwiFmbnWFfGbGY_1tPZg6eXmCTzqYxqLqXFLMgNLWOHPQPO-G77z1KzzkIbBV7xGuCxofVdjXGhHGGeUh7cymg9OGtAghMLDFvCd3kXT-FS",
        "tag":"8FKQxyMz5f7gojQNK3Jtr5xmI3-12_VA4CJteW3fH0A"
    }
    "#;

    const MSG_ANONCRYPT_P256_A256CBC_CHANGED_ENC_KEY: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjpudWxsLCJhcHYiOiJ6LUxxcHZWWERiX3NHWW4zbWpRTHB1dTJDUUxld1l1Wm9UV09JWFBIM0ZNIiwiZXBrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiLXh2cnltSzFLNnN3R0tLZ2VERUJyQmdhSnhWSFd1R09nTU1wTWc2OFRzYyIsInkiOiJGa3hqeUdzdVlQRVZuS3lSQ1l2a3J2ejl6cno3OTFMX2dCcWtzOWc2Y2R3In19",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-p256-1"
                },
                "encrypted_key":"eeussjPSY0lT5zdj_XZgBTylAxa2yBL4Sc6rM7E42p-PsDJF60sdhAj2tm9Zg6POBI09YAy44Sygdw3rbLvcKshj6M9uD3Nc"
            },{
                "header":{
                    "kid":"did:example:bob#key-p256-2"
                },
                "encrypted_key":"s9jBWrES_9Fvnjxof3EDlDM_i3Ds3ry6pXeIOh2n8kp15L3e6CQ2yyNeEmOwuFhVwfUxuRQbM3mVlKLtySh6UtmyzSm0UZpl"
            }],
        "iv":"GIBpOTfWoimvyheRyaDlVQ",
        "ciphertext":"Dk1zcI0w1zyJjaLuaWzbOOLxsaiin1yMqHo2pI--7dJpgNID4YJCbdorekPJO5dcN8JX97DimOsZZyTde5wjZGWhRzTfHwIZT4OK9--gETjifddt2JUk0Dp72lpV35Ie6_5xU8KZEBlcajO5StBWg2sWua3hEpXTq3yJDAEMTp0Sz-CKqMlQ4frqPHJapjOz010-xVIR8cmmLoVOIA2wb5pD3uK8LLYwxUJzR-Eq5dlD6k1TtDCdZQEY38AT7a3QJ4Q49fIkZ7epREn9qLobqZwiFmbnWFfGbGY_1tPZg6eXmCTzqYxqLqXFLMgNLWOHPQPO-G77z1KzzkIbBV7xGuCxofVdjXGhHGGeUh7cymg9OGtAghMLDFvCd3kXT-FS",
        "tag":"8FKQxyMz5f7gojQNK3Jtr5xmI3-12_VA4CJteW3fH0A"
    }
    "#;

    const MSG_ANONCRYPT_P256_A256CBC_CHANGED_CIPHERTEXT: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjpudWxsLCJhcHYiOiJ6LUxxcHZWWERiX3NHWW4zbWpRTHB1dTJDUUxld1l1Wm9UV09JWFBIM0ZNIiwiZXBrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiLXh2cnltSzFLNnN3R0tLZ2VERUJyQmdhSnhWSFd1R09nTU1wTWc2OFRzYyIsInkiOiJGa3hqeUdzdVlQRVZuS3lSQ1l2a3J2ejl6cno3OTFMX2dCcWtzOWc2Y2R3In19",
        "recipients":[{
                "header":{
                    "kid":"did:example:bob#key-p256-1"
                },
                "encrypted_key":"ReussjPSY0lT5zdj_XZgBTylAxa2yBL4Sc6rM7E42p-PsDJF60sdhAj2tm9Zg6POBI09YAy44Sygdw3rbLvcKshj6M9uD3Nc"
            },{
                "header":{
                    "kid":"did:example:bob#key-p256-2"
                },
                "encrypted_key":"s9jBWrES_9Fvnjxof3EDlDM_i3Ds3ry6pXeIOh2n8kp15L3e6CQ2yyNeEmOwuFhVwfUxuRQbM3mVlKLtySh6UtmyzSm0UZpl"
            }],
        "iv":"GIBpOTfWoimvyheRyaDlVQ",
        "ciphertext":"kk1zcI0w1zyJjaLuaWzbOOLxsaiin1yMqHo2pI--7dJpgNID4YJCbdorekPJO5dcN8JX97DimOsZZyTde5wjZGWhRzTfHwIZT4OK9--gETjifddt2JUk0Dp72lpV35Ie6_5xU8KZEBlcajO5StBWg2sWua3hEpXTq3yJDAEMTp0Sz-CKqMlQ4frqPHJapjOz010-xVIR8cmmLoVOIA2wb5pD3uK8LLYwxUJzR-Eq5dlD6k1TtDCdZQEY38AT7a3QJ4Q49fIkZ7epREn9qLobqZwiFmbnWFfGbGY_1tPZg6eXmCTzqYxqLqXFLMgNLWOHPQPO-G77z1KzzkIbBV7xGuCxofVdjXGhHGGeUh7cymg9OGtAghMLDFvCd3kXT-FS",
        "tag":"8FKQxyMz5f7gojQNK3Jtr5xmI3-12_VA4CJteW3fH0A"
    }
    "#;

    const MSG_ANONCRYPT_P256_A256GSM: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwiYXB1IjpudWxsLCJhcHYiOiJ6LUxxcHZWWERiX3NHWW4zbWpRTHB1dTJDUUxld1l1Wm9UV09JWFBIM0ZNIiwiZXBrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoidDZYaDNGTTNna21SZ2dyUTBwMElxb3RDejdNV2tPRWRwNXZRQkNwWW9ZcyIsInkiOiJfNzgzWjRHbGFkQ095VDBFSFczU3FuVldRazNocWlSX2MwVjJGMURZVzhjIn19",
        "recipients":[{
                    "header":{
                        "kid":"did:example:bob#key-p256-1"
                    },
                    "encrypted_key":"ZDH8GpSLzcO3r1Gw-QQPGRCIP3a_LXzeiOCqgecz7-YHBnAPEyF87Q"
                },{
                    "header":{
                        "kid":"did:example:bob#key-p256-2"
                    },
                    "encrypted_key":"J2xoNA3fLYgPVkocnXr4KafSLOhVbMZipRCEkPBuUIF4z2hpP0tdmg"
                }],
        "iv":"MR5gOGVOZvqHVO7n",
        "ciphertext":"QdzPSf5z2yrNYYXgfUAe6-7K3QpppzP3rmzkrlBgmmD_ePdcY0riNvhwBm2Bt_oc0ebK6aq-TKkAoI4P__ISe2TH8RwPuc0HjSkUZtjW8Y8x-wnuED9HEX-HuEAZlM2aFuVy3R_104kbwkAeFtrTTN00ylclOr0ldTXXjTsio58j0Yqrq7Iz6VuScYkdVfJStEswfa4e3BEO_vRAKpr2jVsj6HL5RqZUpCF-DWy_pDsu-IRpYinglvLAfkT6O9g8QApLULOdO4r8TlD1ns-Jx9lLTZZLaILSJZSuzrV6kXgwIOUnyKeA6q2NNbddoxwgpxKGfJ8Bk-Fu0uC8UP_xHVZPRiUd9PyFY6e8dcFNoumu7g4iVN7L",
        "tag":"E5tdRcTYnxaf2p5e4wgNGQ"
    }
    "#;

    const MSG_ANONCRYPT_P256_A256GSM_CHANGED_ENC_KEY: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwiYXB1IjpudWxsLCJhcHYiOiJ6LUxxcHZWWERiX3NHWW4zbWpRTHB1dTJDUUxld1l1Wm9UV09JWFBIM0ZNIiwiZXBrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoidDZYaDNGTTNna21SZ2dyUTBwMElxb3RDejdNV2tPRWRwNXZRQkNwWW9ZcyIsInkiOiJfNzgzWjRHbGFkQ095VDBFSFczU3FuVldRazNocWlSX2MwVjJGMURZVzhjIn19",
        "recipients":[{
                    "header":{
                        "kid":"did:example:bob#key-p256-1"
                    },
                    "encrypted_key":"DDH8GpSLzcO3r1Gw-QQPGRCIP3a_LXzeiOCqgecz7-YHBnAPEyF87Q"
                },{
                    "header":{
                        "kid":"did:example:bob#key-p256-2"
                    },
                    "encrypted_key":"J2xoNA3fLYgPVkocnXr4KafSLOhVbMZipRCEkPBuUIF4z2hpP0tdmg"
                }],
        "iv":"MR5gOGVOZvqHVO7n",
        "ciphertext":"QdzPSf5z2yrNYYXgfUAe6-7K3QpppzP3rmzkrlBgmmD_ePdcY0riNvhwBm2Bt_oc0ebK6aq-TKkAoI4P__ISe2TH8RwPuc0HjSkUZtjW8Y8x-wnuED9HEX-HuEAZlM2aFuVy3R_104kbwkAeFtrTTN00ylclOr0ldTXXjTsio58j0Yqrq7Iz6VuScYkdVfJStEswfa4e3BEO_vRAKpr2jVsj6HL5RqZUpCF-DWy_pDsu-IRpYinglvLAfkT6O9g8QApLULOdO4r8TlD1ns-Jx9lLTZZLaILSJZSuzrV6kXgwIOUnyKeA6q2NNbddoxwgpxKGfJ8Bk-Fu0uC8UP_xHVZPRiUd9PyFY6e8dcFNoumu7g4iVN7L",
        "tag":"E5tdRcTYnxaf2p5e4wgNGQ"
    }
    "#;

    const MSG_ANONCRYPT_P256_A256GSM_CHANGED_CIPHERTEXT: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwiYXB1IjpudWxsLCJhcHYiOiJ6LUxxcHZWWERiX3NHWW4zbWpRTHB1dTJDUUxld1l1Wm9UV09JWFBIM0ZNIiwiZXBrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoidDZYaDNGTTNna21SZ2dyUTBwMElxb3RDejdNV2tPRWRwNXZRQkNwWW9ZcyIsInkiOiJfNzgzWjRHbGFkQ095VDBFSFczU3FuVldRazNocWlSX2MwVjJGMURZVzhjIn19",
        "recipients":[{
                    "header":{
                        "kid":"did:example:bob#key-p256-1"
                    },
                    "encrypted_key":"ZDH8GpSLzcO3r1Gw-QQPGRCIP3a_LXzeiOCqgecz7-YHBnAPEyF87Q"
                },{
                    "header":{
                        "kid":"did:example:bob#key-p256-2"
                    },
                    "encrypted_key":"J2xoNA3fLYgPVkocnXr4KafSLOhVbMZipRCEkPBuUIF4z2hpP0tdmg"
                }],
        "iv":"MR5gOGVOZvqHVO7n",
        "ciphertext":"ddzPSf5z2yrNYYXgfUAe6-7K3QpppzP3rmzkrlBgmmD_ePdcY0riNvhwBm2Bt_oc0ebK6aq-TKkAoI4P__ISe2TH8RwPuc0HjSkUZtjW8Y8x-wnuED9HEX-HuEAZlM2aFuVy3R_104kbwkAeFtrTTN00ylclOr0ldTXXjTsio58j0Yqrq7Iz6VuScYkdVfJStEswfa4e3BEO_vRAKpr2jVsj6HL5RqZUpCF-DWy_pDsu-IRpYinglvLAfkT6O9g8QApLULOdO4r8TlD1ns-Jx9lLTZZLaILSJZSuzrV6kXgwIOUnyKeA6q2NNbddoxwgpxKGfJ8Bk-Fu0uC8UP_xHVZPRiUd9PyFY6e8dcFNoumu7g4iVN7L",
        "tag":"E5tdRcTYnxaf2p5e4wgNGQ"
    }
    "#;

    const MSG_AUTHCRYPT_X25519_A256CBC: &str = r#"
    {
        "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
        "recipients":[
           {
              "encrypted_key":"o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
        "iv":"o02OXDQ6_-sKz2PX_6oyJg"
     }
    "#;

    const MSG_AUTHCRYPT_X25519_A256CBC_CHANGED_ENC_KEY: &str = r#"
    {
        "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
        "recipients":[
           {
              "encrypted_key":"F0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
        "iv":"o02OXDQ6_-sKz2PX_6oyJg"
     }
    "#;

    const MSG_AUTHCRYPT_X25519_A256CBC_CHANGED_CIPHERTEXT: &str = r#"
    {
        "ciphertext":"JJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
        "recipients":[
           {
              "encrypted_key":"o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
        "iv":"o02OXDQ6_-sKz2PX_6oyJg"
     }
    "#;

    const MSG_AUTHCRYPT_P256_A256CBC: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXktcDI1Ni0xIiwiYXB1IjoiWkdsa09tVjRZVzF3YkdVNllXeHBZMlVqYTJWNUxYQXlOVFl0TVEiLCJhcHYiOiJ6LUxxcHZWWERiX3NHWW4zbWpRTHB1dTJDUUxld1l1Wm9UV09JWFBIM0ZNIiwiZXBrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiX05UZFk0Nm9TM0ZtNF9tSWxtV2VGMk9HU1NsdTU1dTJDSVlWMndzdGhDZyIsInkiOiJGcEJxeWlTc0R0NW5jb3laTWFvT3ItYUxNcmNNYW10aWZTYUstRUFrX3NrIn19",
        "recipients":[{
            "header":{
                "kid":"did:example:bob#key-p256-1"
            },
            "encrypted_key":"VokcBeiCnIR5xCpml6oXn2nEmK31hg0aYOWG0EHlgbv19g2oyOPxsxgxuDEkk-oEXj6WNfs_mebxUQLCKpbHh7tTyqnceoh-"
        },{
            "header":{
                "kid":"did:example:bob#key-p256-2"
            },
            "encrypted_key":"LGQRr4jN-DYlR3Vj2NrJOHcT6iZ3FblERiQNd3UxpAmXF9pI9LyG0gWlE9CTEWNN_EK_yvXPg6TCmsVwoA7VNC7tj74oz66t"
        }],
        "iv":"7xtMiG3E7Rjhw_6JEo4S7w",
        "ciphertext":"ebalFD4UYdpFi5p4KDjLYfgJubV5byaCV6V-4qvqF74N4OD_zAZDd7rQxWqds67VwYX2Yw9oTYe_H6WivrCKieHFjqC01gUCbFiqS-lqe3O3WFNnwVX-WRNC7Tsha0azlulJECUXlqyKsuqp-VGYcO-OKyRfzuN_KhBbKAlfxVNxbJX-9ecb0ZqtiZRcOGvqrcDRCgQ8ApdcwGelBLs6V0bBIYnsMHkxi1eK4dMmhBpMoKR9GwQxSwBnKEs5BMO-NTRyAWWKHZXraC8nWSBivqGR9TocrD5H0xK5Ys9eUPJr453BbwTTX2BFdZQlrv4zBwHsaqsHdWPhuQyzjmQFgbmOPOtmnwSurVMRO8A1fZtbWiKy9CYqffqL8XyWmH-S","tag":"84reUHzWkfJsr6rtPMEV40gL8wswp2--V-cwmHOQt5o"
    }
    "#;

    const MSG_AUTHCRYPT_P256_A256CBC_CHANGED_ENC_KEY: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXktcDI1Ni0xIiwiYXB1IjoiWkdsa09tVjRZVzF3YkdVNllXeHBZMlVqYTJWNUxYQXlOVFl0TVEiLCJhcHYiOiJ6LUxxcHZWWERiX3NHWW4zbWpRTHB1dTJDUUxld1l1Wm9UV09JWFBIM0ZNIiwiZXBrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiX05UZFk0Nm9TM0ZtNF9tSWxtV2VGMk9HU1NsdTU1dTJDSVlWMndzdGhDZyIsInkiOiJGcEJxeWlTc0R0NW5jb3laTWFvT3ItYUxNcmNNYW10aWZTYUstRUFrX3NrIn19",
        "recipients":[{
            "header":{
                "kid":"did:example:bob#key-p256-1"
            },
            "encrypted_key":"ookcBeiCnIR5xCpml6oXn2nEmK31hg0aYOWG0EHlgbv19g2oyOPxsxgxuDEkk-oEXj6WNfs_mebxUQLCKpbHh7tTyqnceoh-"
        },{
            "header":{
                "kid":"did:example:bob#key-p256-2"
            },
            "encrypted_key":"LGQRr4jN-DYlR3Vj2NrJOHcT6iZ3FblERiQNd3UxpAmXF9pI9LyG0gWlE9CTEWNN_EK_yvXPg6TCmsVwoA7VNC7tj74oz66t"
        }],
        "iv":"7xtMiG3E7Rjhw_6JEo4S7w",
        "ciphertext":"ebalFD4UYdpFi5p4KDjLYfgJubV5byaCV6V-4qvqF74N4OD_zAZDd7rQxWqds67VwYX2Yw9oTYe_H6WivrCKieHFjqC01gUCbFiqS-lqe3O3WFNnwVX-WRNC7Tsha0azlulJECUXlqyKsuqp-VGYcO-OKyRfzuN_KhBbKAlfxVNxbJX-9ecb0ZqtiZRcOGvqrcDRCgQ8ApdcwGelBLs6V0bBIYnsMHkxi1eK4dMmhBpMoKR9GwQxSwBnKEs5BMO-NTRyAWWKHZXraC8nWSBivqGR9TocrD5H0xK5Ys9eUPJr453BbwTTX2BFdZQlrv4zBwHsaqsHdWPhuQyzjmQFgbmOPOtmnwSurVMRO8A1fZtbWiKy9CYqffqL8XyWmH-S","tag":"84reUHzWkfJsr6rtPMEV40gL8wswp2--V-cwmHOQt5o"
    }
    "#;

    const MSG_AUTHCRYPT_P256_A256CBC_CHANGED_CIPHERTEXT: &str = r#"
    {
        "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXktcDI1Ni0xIiwiYXB1IjoiWkdsa09tVjRZVzF3YkdVNllXeHBZMlVqYTJWNUxYQXlOVFl0TVEiLCJhcHYiOiJ6LUxxcHZWWERiX3NHWW4zbWpRTHB1dTJDUUxld1l1Wm9UV09JWFBIM0ZNIiwiZXBrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiX05UZFk0Nm9TM0ZtNF9tSWxtV2VGMk9HU1NsdTU1dTJDSVlWMndzdGhDZyIsInkiOiJGcEJxeWlTc0R0NW5jb3laTWFvT3ItYUxNcmNNYW10aWZTYUstRUFrX3NrIn19",
        "recipients":[{
            "header":{
                "kid":"did:example:bob#key-p256-1"
            },
            "encrypted_key":"VokcBeiCnIR5xCpml6oXn2nEmK31hg0aYOWG0EHlgbv19g2oyOPxsxgxuDEkk-oEXj6WNfs_mebxUQLCKpbHh7tTyqnceoh-"
        },{
            "header":{
                "kid":"did:example:bob#key-p256-2"
            },
            "encrypted_key":"LGQRr4jN-DYlR3Vj2NrJOHcT6iZ3FblERiQNd3UxpAmXF9pI9LyG0gWlE9CTEWNN_EK_yvXPg6TCmsVwoA7VNC7tj74oz66t"
        }],
        "iv":"7xtMiG3E7Rjhw_6JEo4S7w",
        "ciphertext":"bbalFD4UYdpFi5p4KDjLYfgJubV5byaCV6V-4qvqF74N4OD_zAZDd7rQxWqds67VwYX2Yw9oTYe_H6WivrCKieHFjqC01gUCbFiqS-lqe3O3WFNnwVX-WRNC7Tsha0azlulJECUXlqyKsuqp-VGYcO-OKyRfzuN_KhBbKAlfxVNxbJX-9ecb0ZqtiZRcOGvqrcDRCgQ8ApdcwGelBLs6V0bBIYnsMHkxi1eK4dMmhBpMoKR9GwQxSwBnKEs5BMO-NTRyAWWKHZXraC8nWSBivqGR9TocrD5H0xK5Ys9eUPJr453BbwTTX2BFdZQlrv4zBwHsaqsHdWPhuQyzjmQFgbmOPOtmnwSurVMRO8A1fZtbWiKy9CYqffqL8XyWmH-S","tag":"84reUHzWkfJsr6rtPMEV40gL8wswp2--V-cwmHOQt5o"
    }
    "#;

    const MSG_ECDH_1PU_APP_B: &str = r#"
    {
        "protected":"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19",
        "recipients":[
            {
                "header":{
                    "kid":"bob-key-2"
                },
                "encrypted_key":"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"
            },
            {
                "header":{
                    "kid":"2021-05-06"
                },
                "encrypted_key": "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE"
            }
        ],
        "iv":"AAECAwQFBgcICQoLDA0ODw",
        "ciphertext":"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
        "tag":"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"
    }
    "#;

    const PAYLOAD_ECDH_1PU_APP_B: &str = "Three is a magic number.";

    const ALICE_KID_ECDH_1PU_APP_B: &str = "Alice";

    const ALICE_KEY_ECDH_1PU_APP_B: &str = r#"
    {
        "kty": "OKP",
        "crv": "X25519",
        "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
        "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU"
    }
    "#;

    const BOB_KID_ECDH_1PU_APP_B: &str = "bob-key-2";

    const BOB_KEY_ECDH_1PU_APP_B: &str = r#"
    {
        "kty": "OKP",
        "crv": "X25519",
        "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
        "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg"
    }
    "#;

    const CHARLIE_KID_ECDH_1PU_APP_B: &str = "2021-05-06";

    const CHARLIE_KEY_ECDH_1PU_APP_B: &str = r#"
    {
        "kty": "OKP",
        "crv": "X25519",
        "x": "q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE",
        "d": "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE"
    }
    "#;
}
