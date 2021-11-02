use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext},
    jws::{self, Algorithm},
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyPair},
        did::did_or_url,
    },
    Message, PackPlaintextOptions,
};

impl Message {
    /// Produces `DIDComm Signed Message`
    /// https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-message.
    ///
    /// Signed messages are not necessary to provide message integrity (tamper evidence),
    /// or to prove the sender to the recipient. Both of these guarantees automatically occur
    /// with the authenticated encryption in DIDComm encrypted messages. Signed messages are only
    /// necessary when the origin of plaintext must be provable to third parties,
    /// or when the sender can’t be proven to the recipient by authenticated encryption because
    /// the recipient is not known in advance (e.g., in a broadcast scenario).
    /// We therefore expect signed messages to be used in a few cases, but not as a matter of course.
    ///
    /// # Parameters
    /// - `sign_by` a DID or key ID the sender uses for signing
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
    ///
    /// # Returns
    /// Tuple (signed_message, metadata)
    /// - `signed_message` a DIDComm signed message as JSON string
    /// - `metadata` additional metadata about this `encrypt` execution like used keys identifiers and algorithms.
    ///
    /// # Errors
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotResolved` DID doesn't contain mentioned DID Urls (for ex., key id)
    /// - `SecretNotFound` Sender secret is not found.
    /// - `Unsupported` Used crypto or method is unsupported.
    /// - `InvalidState` Indicates library error.
    /// - `IOError` IO error during DID or secrets resolving
    /// TODO: verify and update errors list
    pub async fn pack_signed<'dr, 'sr>(
        &self,
        sign_by: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &PackSignedOptions,
    ) -> Result<(String, PackSignedMetadata)> {
        let (did, key_id) = did_or_url(sign_by);

        let did_doc = did_resolver
            .resolve(did)
            .await
            .context("Unable resolve signer did")?
            .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Signer did not found"))?;

        let authentications: Vec<_> = if let Some(key_id) = key_id {
            did_doc
                .authentications
                .iter()
                .find(|a| *a == key_id)
                .ok_or_else(|| {
                    err_msg(
                        ErrorKind::DIDUrlNotFound,
                        "Signer key id not found in did doc",
                    )
                })?;

            vec![key_id]
        } else {
            did_doc.authentications.iter().map(|s| s.as_str()).collect()
        };

        let key_id = *secrets_resolver
            .find_secrets(&authentications)
            .await
            .context("Unable find secrets")?
            .get(0)
            .ok_or_else(|| err_msg(ErrorKind::SecretNotFound, "No signer secrets found"))?;

        let secret = secrets_resolver
            .get_secret(key_id)
            .await
            .context("Unable get secret")?
            .ok_or_else(|| err_msg(ErrorKind::SecretNotFound, "Signer secret not found"))?;

        let sign_key = secret
            .as_key_pair()
            .context("Unable instantiate sign key")?;

        let (payload, pack_plaintext_metadata) = self
            .pack_plaintext(
                did_resolver,
                secrets_resolver,
                &PackPlaintextOptions {
                    from_prior_issuer_kid: options.from_prior_issuer_kid.clone(),
                },
            )
            .await?;

        let msg = match sign_key {
            KnownKeyPair::Ed25519(ref key) => {
                jws::sign(payload.as_bytes(), (key_id, key), Algorithm::EdDSA)
            }
            KnownKeyPair::P256(ref key) => {
                jws::sign(payload.as_bytes(), (key_id, key), Algorithm::Es256)
            }
            KnownKeyPair::K256(ref key) => {
                jws::sign(payload.as_bytes(), (key_id, key), Algorithm::Es256K)
            }
            _ => Err(err_msg(ErrorKind::Unsupported, "Unsupported signature alg"))?,
        }
        .context("Unable produce signatire")?;

        let metadata = PackSignedMetadata {
            sign_by_kid: key_id.to_owned(),
            from_prior_issuer_kid: pack_plaintext_metadata.from_prior_issuer_kid,
        };

        Ok((msg, metadata))
    }
}

/// Allow fine configuration of packing process.
#[derive(Debug, PartialEq, Eq)]
pub struct PackSignedOptions {
    // Identifier (DID URL) of from_prior issuer key
    pub from_prior_issuer_kid: Option<String>,
}

impl Default for PackSignedOptions {
    fn default() -> Self {
        PackSignedOptions {
            from_prior_issuer_kid: None,
        }
    }
}

/// Additional metadata about this `pack` method execution like used key identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSignedMetadata {
    /// Identifier (DID URL) of sign key.
    pub sign_by_kid: String,

    // Identifier (DID URL) of from_prior issuer key.
    pub from_prior_issuer_kid: Option<String>,
}

#[cfg(test)]
mod tests {
    use askar_crypto::{
        alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair},
        sign::KeySigVerify,
    };

    use serde_json::Value;

    use crate::{
        did::{resolvers::ExampleDIDResolver, DIDResolver, VerificationMaterial},
        jwk::FromJwkValue,
        jws::{self, Algorithm, Header, ProtectedHeader},
        secrets::{resolvers::ExampleSecretsResolver, SecretsResolver},
        test_vectors::{
            ALICE_AUTH_METHOD_25519, ALICE_AUTH_METHOD_P256, ALICE_AUTH_METHOD_SECPP256K1,
            ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID,
            CHARLIE_DID_DOC, CHARLIE_ROTATED_TO_ALICE_SECRETS, CHARLIE_SECRET_AUTH_KEY_ED25519,
            MESSAGE_FROM_PRIOR, MESSAGE_FROM_PRIOR_MINIMAL, MESSAGE_SIMPLE, PLAINTEXT_MSG_SIMPLE,
        },
        utils::did::did_or_url,
        Message, PackSignedMetadata, PackSignedOptions, UnpackOptions,
    };

    #[tokio::test]
    async fn pack_signed_works() {
        let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        _pack_signed_works::<Ed25519KeyPair>(
            &did_resolver,
            &secrets_resolver,
            &MESSAGE_SIMPLE,
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            Algorithm::EdDSA,
            PLAINTEXT_MSG_SIMPLE,
            &ALICE_DID_DOC.verification_methods[4].verification_material,
        )
        .await;

        _pack_signed_works::<Ed25519KeyPair>(
            &did_resolver,
            &secrets_resolver,
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            Algorithm::EdDSA,
            PLAINTEXT_MSG_SIMPLE,
            &ALICE_DID_DOC.verification_methods[4].verification_material,
        )
        .await;

        _pack_signed_works::<P256KeyPair>(
            &did_resolver,
            &secrets_resolver,
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256.id,
            Algorithm::Es256,
            PLAINTEXT_MSG_SIMPLE,
            &ALICE_DID_DOC.verification_methods[5].verification_material,
        )
        .await;

        _pack_signed_works::<K256KeyPair>(
            &did_resolver,
            &secrets_resolver,
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            Algorithm::Es256K,
            PLAINTEXT_MSG_SIMPLE,
            &ALICE_DID_DOC.verification_methods[6].verification_material,
        )
        .await;

        async fn _pack_signed_works<Key: KeySigVerify + FromJwkValue, 'dr, 'sr>(
            did_resolver: &'dr (dyn DIDResolver + 'dr),
            secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
            message: &Message,
            sign_by: &str,
            sign_by_kid: &str,
            alg: Algorithm,
            plaintext: &str,
            verification_material: &VerificationMaterial,
        ) {
            let (msg, metadata) = message
                .pack_signed(
                    sign_by,
                    did_resolver,
                    secrets_resolver,
                    &PackSignedOptions::default(),
                )
                .await
                .expect("Unable pack_signed");

            assert_eq!(
                metadata,
                PackSignedMetadata {
                    sign_by_kid: sign_by_kid.into(),
                    from_prior_issuer_kid: None,
                }
            );

            let mut buf = vec![];
            let msg = jws::parse(&msg, &mut buf).expect("Unable parse");

            assert_eq!(
                msg.protected,
                vec![ProtectedHeader {
                    typ: "application/didcomm-signed+json",
                    alg,
                }]
            );

            let payload: Value = {
                let payload = base64::decode_config(msg.jws.payload, base64::URL_SAFE_NO_PAD)
                    .expect("Unable decode_config");

                serde_json::from_slice(&payload).expect("Unable from_str")
            };

            let exp_payload: Value = serde_json::from_str(plaintext).expect("Unable from_str");

            assert_eq!(payload, exp_payload);
            assert_eq!(msg.jws.signatures.len(), 1);

            assert_eq!(
                msg.jws.signatures[0].header,
                Header {
                    kid: sign_by_kid.into()
                }
            );

            let signer_key = match verification_material {
                VerificationMaterial::JWK(ref jwk) => {
                    Key::from_jwk_value(jwk).expect("Unable from_jwk_value")
                }
                _ => panic!("Unexpected verification_material"),
            };

            let valid = msg
                .verify((sign_by_kid, &signer_key))
                .expect("Unable verify");

            assert!(valid);
        }
    }

    #[tokio::test]
    async fn pack_signed_works_from_prior_and_issuer_kid() {
        _pack_signed_works_from_prior_and_issuer_kid(&MESSAGE_FROM_PRIOR_MINIMAL).await;
        _pack_signed_works_from_prior_and_issuer_kid(&MESSAGE_FROM_PRIOR).await;

        async fn _pack_signed_works_from_prior_and_issuer_kid(msg: &Message) {
            let did_resolver = ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                BOB_DID_DOC.clone(),
                CHARLIE_DID_DOC.clone(),
            ]);
            let charlie_rotated_to_alice_secrets_resolver =
                ExampleSecretsResolver::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());
            let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

            let (packed_msg, pack_metadata) = msg
                .pack_signed(
                    ALICE_DID,
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                    &PackSignedOptions {
                        from_prior_issuer_kid: Some(CHARLIE_SECRET_AUTH_KEY_ED25519.id.clone()),
                    },
                )
                .await
                .expect("Unable pack_signed");

            assert_eq!(
                pack_metadata.from_prior_issuer_kid,
                Some(CHARLIE_SECRET_AUTH_KEY_ED25519.id.clone())
            );

            let (unpacked_msg, unpack_metadata) = Message::unpack(
                &packed_msg,
                &did_resolver,
                &bob_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            assert_eq!(&unpacked_msg, msg);
            assert_eq!(
                unpack_metadata.from_prior_issuer_kid,
                Some(CHARLIE_SECRET_AUTH_KEY_ED25519.id.clone())
            );
            assert!(unpack_metadata.from_prior_jwt.is_some());
        }
    }

    #[tokio::test]
    async fn pack_signed_works_from_prior_and_no_issuer_kid() {
        _pack_signed_with_from_prior_works_and_no_issuer_kid(&MESSAGE_FROM_PRIOR_MINIMAL).await;
        _pack_signed_with_from_prior_works_and_no_issuer_kid(&MESSAGE_FROM_PRIOR).await;

        async fn _pack_signed_with_from_prior_works_and_no_issuer_kid(msg: &Message) {
            let did_resolver = ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                BOB_DID_DOC.clone(),
                CHARLIE_DID_DOC.clone(),
            ]);
            let charlie_rotated_to_alice_secrets_resolver =
                ExampleSecretsResolver::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());
            let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

            let (packed_msg, pack_metadata) = msg
                .pack_signed(
                    ALICE_DID,
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                    &PackSignedOptions::default(),
                )
                .await
                .expect("Unable pack_signed");

            assert!(pack_metadata.from_prior_issuer_kid.is_some());

            let (did, kid) = did_or_url(pack_metadata.from_prior_issuer_kid.as_deref().unwrap());
            assert!(kid.is_some());
            assert_eq!(did, CHARLIE_DID);

            let (unpacked_msg, unpack_metadata) = Message::unpack(
                &packed_msg,
                &did_resolver,
                &bob_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            assert_eq!(&unpacked_msg, msg);
            assert_eq!(
                unpack_metadata.from_prior_issuer_kid,
                pack_metadata.from_prior_issuer_kid
            );
            assert!(unpack_metadata.from_prior_jwt.is_some());
        }
    }
}
