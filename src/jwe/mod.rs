// TODO: remove allow
#[allow(dead_code)]
mod encrypt;

// TODO: remove allow
#[allow(dead_code)]
mod decrypt;

// TODO: remove allow
#[allow(dead_code)]
mod parse;

// TODO: remove allow
#[allow(dead_code)]
pub(crate) mod envelope;

// TODO: remove allow
#[allow(unused_imports)]
pub(crate) use encrypt::encrypt;

// TODO: remove allow
#[allow(unused_imports)]
pub(crate) use parse::{parse, ParsedJWE};

#[cfg(test)]
mod tests {
    use askar_crypto::{
        alg::{
            aes::{A128CbcHs256, A256Gcm, A256Kw, AesKey},
            chacha20::{Chacha20Key, XC20P},
            p256::P256KeyPair,
            x25519::X25519KeyPair,
        },
        encrypt::{KeyAeadInPlace, KeyAeadMeta},
        jwk::{FromJwk, ToJwk},
        kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, FromKeyDerivation, KeyExchange},
        repr::{KeyGen, KeyPublicBytes, KeySecretBytes, ToPublicBytes, ToSecretBytes},
    };

    use crate::{
        jwe::{
            self,
            envelope::{Algorithm, EncAlgorithm},
        },
        utils::crypto::{JoseKDF, KeyWrap},
    };

    #[test]
    fn authcrypt_works() {
        _authcrypt_works::<
            AesKey<A128CbcHs256>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >();

        _authcrypt_works::<
            AesKey<A128CbcHs256>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >();

        /// TODO: P-384 and P-521 support after solving https://github.com/hyperledger/aries-askar/issues/10

        fn _authcrypt_works<CE, KDF, KE, KW>()
        where
            CE: KeyAeadInPlace + KeyAeadMeta + KeyGen + ToSecretBytes + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwk + FromJwk + ToPublicBytes + KeyPublicBytes,
            KW: KeyWrap + FromKeyDerivation,
        {
            let alice_kid = "did:example:alice#key-1";
            let alice_key = KE::random().expect("unable random.");

            let alice_pkey = {
                let bytes = alice_key
                    .to_public_bytes()
                    .expect("unable to_public_bytes.");

                KE::from_public_bytes(&bytes).expect("unable from_public_bytes.")
            };

            let bob_kid = "did:example:bob#key-1";
            let bob_key = KE::random().expect("unable random.");

            let bob_pkey = {
                let bytes = bob_key.to_public_bytes().expect("unable to_public_bytes.");

                KE::from_public_bytes(&bytes).expect("unable from_public_bytes.")
            };

            let plaintext = "Some plaintext.";

            let msg = jwe::encrypt::<CE, KDF, KE, KW>(
                plaintext.as_bytes(),
                Algorithm::Ecdh1puA256kw,
                EncAlgorithm::A256cbcHs512,
                Some((alice_kid, &alice_key)),
                &[(bob_kid, &bob_pkey)],
            )
            .expect("unable encrypt.");

            let mut buf = Vec::new();
            let msg = jwe::parse(&msg, &mut buf).expect("unable parse.");

            assert_eq!(msg.jwe.recipients.len(), 1);
            assert_eq!(msg.jwe.recipients[0].header.kid, bob_kid);

            assert_eq!(msg.protected.alg, Algorithm::Ecdh1puA256kw);
            assert_eq!(msg.protected.enc, EncAlgorithm::A256cbcHs512);

            assert_eq!(msg.skid.as_deref(), Some(alice_kid));

            let plaintext_ = msg
                .decrypt::<CE, KDF, KE, KW>(Some((alice_kid, &alice_pkey)), (bob_kid, &bob_key))
                .expect("unable decrypt.");

            assert_eq!(plaintext_, plaintext.as_bytes());
        }
    }

    #[test]
    fn anoncrypt_works() {
        _anoncrypt_works::<
            AesKey<A128CbcHs256>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >();

        _anoncrypt_works::<
            AesKey<A128CbcHs256>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >();

        _anoncrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, X25519KeyPair>, X25519KeyPair, AesKey<A256Kw>>(
        );

        _anoncrypt_works::<AesKey<A256Gcm>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>();

        _anoncrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >();

        _anoncrypt_works::<Chacha20Key<XC20P>, EcdhEs<'_, P256KeyPair>, P256KeyPair, AesKey<A256Kw>>(
        );

        /// TODO: P-384 and P-521 support after solving https://github.com/hyperledger/aries-askar/issues/10

        fn _anoncrypt_works<CE, KDF, KE, KW>()
        where
            CE: KeyAeadInPlace + KeyAeadMeta + KeyGen + ToSecretBytes + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwk + FromJwk + ToPublicBytes + KeyPublicBytes,
            KW: KeyWrap + FromKeyDerivation,
        {
            let bob_kid = "did:example:bob#key-1";
            let bob_key = KE::random().expect("unable random.");

            let bob_pkey = {
                let bytes = bob_key.to_public_bytes().expect("unable to_public_bytes.");

                KE::from_public_bytes(&bytes).expect("unable from_public_bytes.")
            };

            let plaintext = "Some plaintext.";

            let msg = jwe::encrypt::<CE, KDF, KE, KW>(
                plaintext.as_bytes(),
                Algorithm::Ecdh1esA256kw,
                EncAlgorithm::A256cbcHs512,
                None,
                &[(bob_kid, &bob_pkey)],
            )
            .expect("unable encrypt.");

            let mut buf = Vec::new();
            let msg = jwe::parse(&msg, &mut buf).expect("unable parse.");

            assert_eq!(msg.jwe.recipients.len(), 1);
            assert_eq!(msg.jwe.recipients[0].header.kid, "did:example:bob#key-1");

            assert_eq!(msg.protected.alg, Algorithm::Ecdh1esA256kw);
            assert_eq!(msg.protected.enc, EncAlgorithm::A256cbcHs512);

            assert_eq!(msg.skid, None);

            let _plaintext = msg
                .decrypt::<CE, KDF, KE, KW>(None, (bob_kid, &bob_key))
                .expect("unable decrypt.");

            assert_eq!(_plaintext, plaintext.as_bytes());
        }
    }
}
