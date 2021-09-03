// TODO: Remove allow
#[allow(dead_code)]
mod envelope;

// TODO: Remove allow
#[allow(dead_code)]
mod parse;

// TODO: Remove allow
#[allow(dead_code)]
mod sign;

// TODO: Remove allow
#[allow(dead_code)]
mod verify;

// TODO: Remove allow
#[allow(unused_imports)]
pub(crate) use sign::sign;

// TODO: Remove allow
#[allow(unused_imports)]
pub(crate) use parse::{parse, ParsedJWS};

#[cfg(test)]
mod tests {
    use askar_crypto::{
        alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair},
        repr::{KeyGen, KeyPublicBytes, ToPublicBytes},
        sign::KeySign,
    };

    use crate::jws::{self, envelope::Algorithm};

    #[test]
    fn sign_verify_works() {
        _sign_verify_works::<Ed25519KeyPair>(Algorithm::EdDSA);

        // TODO: Uncomment after fixing https://github.com/hyperledger/aries-askar/issues/26
        //_sign_verify_works::<P256KeyPair>(Algorithm::Es256);

        _sign_verify_works::<K256KeyPair>(Algorithm::Es256K);

        fn _sign_verify_works<Key>(alg: Algorithm)
        where
            Key: KeySign + KeyGen + ToPublicBytes + KeyPublicBytes,
        {
            let alice_kid = "did:example:alice#key-1";
            let alice_key = Key::random().expect("unable random.");

            let alice_pkey = {
                let bytes = alice_key
                    .to_public_bytes()
                    .expect("unable to_public_bytes.");

                Key::from_public_bytes(&bytes).expect("unable from_public_bytes.")
            };

            let payload = "Some payload.";

            let msg = jws::sign(payload.as_bytes(), (&alice_kid, &alice_key), alg.clone())
                .expect("unable sign.");

            let mut buf = vec![];
            let msg = jws::parse(&msg, &mut buf).expect("unable parse.");

            assert_eq!(
                msg.jws.payload,
                base64::encode_config(payload, base64::URL_SAFE_NO_PAD)
            );

            assert_eq!(msg.jws.signatures.len(), 1);
            assert_eq!(msg.jws.signatures[0].header.kid, alice_kid);

            assert_eq!(msg.protected.len(), 1);
            assert_eq!(msg.protected[0].alg, alg);
            assert_eq!(msg.protected[0].typ, "application/didcomm-signed+json");

            let valid = msg
                .verify((alice_kid, &alice_pkey))
                .expect("unable verify.");

            assert!(valid);
        }
    }
}
