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
pub(crate) use envelope::{Algorithm, CompactHeader, Header, ProtectedHeader, Signature, JWS};

// TODO: Remove allow
#[allow(unused_imports)]
pub(crate) use sign::{sign, sign_compact};

// TODO: Remove allow
#[allow(unused_imports)]
pub(crate) use parse::{parse, parse_compact, ParsedCompactJWS, ParsedJWS};

#[cfg(test)]
mod tests {
    use askar_crypto::{alg::ed25519::Ed25519KeyPair, jwk::FromJwk};

    use crate::jws::{self, Algorithm};
    use crate::secrets::resolvers::example::{Secret, SecretMaterial, SecretType};
    use crate::secrets::resolvers::ExampleKMS;

    #[tokio::test]
    async fn demo_works() {
        // Identifier of Alice key
        let alice_kid = "did:example:alice#key-1";

        // Alice private key
        let alice_secret = Secret {
            id: alice_kid.to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: serde_json::from_str(
                    r#"
            {
                "kty":"OKP",
                "d":"pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                "crv":"Ed25519",
                "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
            }
            "#,
                )
                .expect("Unable from_jwk"),
            },
        };
        let kms = ExampleKMS::new(vec![alice_secret]);

        // Alice public key
        let alice_pkey = Ed25519KeyPair::from_jwk(
            r#"
            {
                "kty":"OKP",
                "crv":"Ed25519",
                "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
            }
            "#,
        )
        .expect("Unable from_jwk");

        // Message payload
        let payload = "Hello World!";

        // Produce signed message

        let msg = jws::sign(payload.as_bytes(), alice_kid, Algorithm::EdDSA, &kms)
            .await
            .expect("unable sign");

        // Parse message

        let mut buf = vec![];
        let msg = jws::parse(&msg, &mut buf).expect("Unable parse");

        // Verify signature

        let valid = msg
            .verify((alice_kid, &alice_pkey))
            .expect("Unable verify.");

        assert!(valid);
    }
}
