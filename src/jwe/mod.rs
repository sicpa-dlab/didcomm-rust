mod compose;
mod decrypt;
mod parse;

pub(crate) mod envelope;

pub(crate) use compose::compose;
pub(crate) use parse::{parse, ParsedJWE};

#[cfg(test)]
mod tests {
    use askar_crypto::{
        alg::{
            aes::{A128CbcHs256, A256Kw, AesKey},
            x25519::X25519KeyPair,
        },
        kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs},
        repr::KeyGen,
    };

    use crate::jwe::{
        self,
        envelope::{Algorithm, EncAlgorithm},
    };

    #[test]
    fn authcrypt_works() {
        let alice_kid = "did:example:alice#key-1";
        let alice_key = X25519KeyPair::random().expect("unable random.");

        let bob_kid = "did:example:bob#key-1";
        let bob_key = X25519KeyPair::random().expect("unable random.");

        let msg = jwe::compose::<
            AesKey<A128CbcHs256>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            "Some private message".as_bytes(),
            Algorithm::Ecdh1puA256kw,
            EncAlgorithm::A256cbcHs512,
            Some((alice_kid, &alice_key)),
            &[(bob_kid, &bob_key)],
        )
        .expect("unable compose.");

        let mut buf = Vec::new();
        let msg = jwe::parse(&msg, &mut buf).expect("unable parse.");

        assert_eq!(msg.jwe.recipients.len(), 1);
        assert_eq!(msg.jwe.recipients[0].header.kid, "did:example:bob#key-1");

        assert_eq!(msg.protected.alg, Algorithm::Ecdh1puA256kw);
        assert_eq!(msg.protected.enc, EncAlgorithm::A256cbcHs512);

        assert_eq!(msg.skid.as_deref(), Some("did:example:alice#key-1"));

        let plaintext = msg
            .decrypt::<AesKey<A128CbcHs256>, Ecdh1PU<'_, X25519KeyPair>, X25519KeyPair, AesKey<A256Kw>>(
                Some((alice_kid, &alice_key)),
                (bob_kid, &bob_key),
            )
            .expect("unable decrypt.");

        assert_eq!(plaintext, "Some private message".as_bytes());
    }

    #[test]
    fn anoncrypt_works() {
        let bob_kid = "did:example:bob#key-1";
        let bob_key = X25519KeyPair::random().expect("unable random.");

        let msg = jwe::compose::<
            AesKey<A128CbcHs256>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            "Some private message".as_bytes(),
            Algorithm::Ecdh1esA256kw,
            EncAlgorithm::A256cbcHs512,
            None,
            &[(bob_kid, &bob_key)],
        )
        .expect("unable compose.");

        let mut buf = Vec::new();
        let msg = jwe::parse(&msg, &mut buf).expect("unable parse.");

        assert_eq!(msg.jwe.recipients.len(), 1);
        assert_eq!(msg.jwe.recipients[0].header.kid, "did:example:bob#key-1");

        assert_eq!(msg.protected.alg, Algorithm::Ecdh1esA256kw);
        assert_eq!(msg.protected.enc, EncAlgorithm::A256cbcHs512);

        assert_eq!(msg.skid, None);

        let plaintext = msg
            .decrypt::<AesKey<A128CbcHs256>, EcdhEs<'_, X25519KeyPair>, X25519KeyPair, AesKey<A256Kw>>(
                None,
                (bob_kid, &bob_key),
            )
            .expect("unable decrypt.");

        assert_eq!(plaintext, "Some private message".as_bytes());
    }
}
