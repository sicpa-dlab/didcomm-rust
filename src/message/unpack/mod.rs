mod anoncrypt;
mod authcrypt;
mod sign;

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg, SignAlg},
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultExt},
    secrets::SecretsResolver,
    Message,
};

use anoncrypt::_try_unpack_anoncrypt;
use authcrypt::_try_unpack_authcrypt;
use sign::_try_unapck_sign;

impl Message {
    /// Unpacks the packed message by doing decryption and verifying the signatures.
    /// This method supports all DID Comm message types (encrypted, signed, plaintext).
    ///
    /// If unpack options expect a particular property (for example that a message is encrypted)
    /// and the packed message doesn't meet the criteria (it's not encrypted), then a MessageUntrusted
    /// error will be returned.
    ///
    /// # Params
    /// - `packed_msg` the message as JSON string to be unpacked
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
    /// - `options` allow fine configuration of unpacking process and imposing additional restrictions
    /// to message to be trusted.
    ///
    /// # Returns
    /// Tuple `(message, metadata)`.
    /// - `message` plain message instance
    /// - `metadata` additional metadata about this `unpack` execution like used keys identifiers,
    ///   trust context, algorithms and etc.
    ///
    /// # Errors
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotResolved` DID doesn't contain mentioned DID Urls (for ex., key id)
    /// - `MessageMalformed` message doesn't correspond to DID Comm or has invalid encryption or signatures.
    /// - `UnsatisfiedConstraint` message doesn't satisfy checks requested by unpack options.
    /// - `Unsupported` Used crypto or method is unsupported.
    /// - `SecretNotFound` No recipient secrets found.
    /// - `InvalidState` Indicates library error.
    /// - `IOError` IO error during DID or secrets resolving.
    /// TODO: verify and update errors list
    pub async fn unpack<'dr, 'sr>(
        msg: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &UnpackOptions,
    ) -> Result<(Self, UnpackMetadata)> {
        if options.unwrap_re_wrapping_forward {
            Err(err_msg(
                ErrorKind::Unsupported,
                "Forward unwrapping is unsupported by this version",
            ))?;
        }

        let mut metadata = UnpackMetadata {
            encrypted: false,
            authenticated: false,
            non_repudiation: false,
            anonymous_sender: false,
            re_wrapped_in_forward: false,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            signed_plaintext: None,
        };

        let anoncryted =
            _try_unpack_anoncrypt(msg, secrets_resolver, options, &mut metadata).await?;

        let msg = anoncryted.as_deref().unwrap_or(msg);

        let authcrypted =
            _try_unpack_authcrypt(msg, did_resolver, secrets_resolver, options, &mut metadata)
                .await?;

        let msg = authcrypted.as_deref().unwrap_or(msg);

        let signed = _try_unapck_sign(msg, did_resolver, options, &mut metadata).await?;

        let msg = signed.as_deref().unwrap_or(msg);

        let msg: Self =
            serde_json::from_str(msg).kind(ErrorKind::Malformed, "Unable deserialize jwm")?;

        Ok((msg, metadata))
    }
}

/// Allows fine customization of unpacking process
pub struct UnpackOptions {
    /// Whether the plaintext must be decryptable by all keys resolved by the secrets resolver. False by default.
    pub expect_decrypt_by_all_keys: bool,

    /// If `true` and the packed message is a `Forward`
    /// wrapping a plaintext packed for the given recipient, then both Forward and packed plaintext are unpacked automatically,
    /// and the unpacked plaintext will be returned instead of unpacked Forward.
    /// False by default.
    pub unwrap_re_wrapping_forward: bool,
}

impl Default for UnpackOptions {
    fn default() -> Self {
        UnpackOptions {
            expect_decrypt_by_all_keys: false,

            // TODO: make it true before first stable release
            unwrap_re_wrapping_forward: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnpackMetadata {
    /// Whether the plaintext has been encrypted
    pub encrypted: bool,

    /// Whether the plaintext has been authenticated
    pub authenticated: bool,

    /// Whether the plaintext has been signed
    pub non_repudiation: bool,

    /// Whether the sender ID was protected
    pub anonymous_sender: bool,

    /// Whether the plaintext was re-wrapped in a forward message by a mediator
    pub re_wrapped_in_forward: bool,

    /// Key ID of the sender used for authentication encryption if the plaintext has been authenticated and encrypted
    pub encrypted_from_kid: Option<String>,

    /// Target key IDS for encryption if the plaintext has been encrypted
    pub encrypted_to_kids: Option<Vec<String>>,

    /// Key ID used for signature if the plaintext has been signed
    pub sign_from: Option<String>,

    /// Algorithm used for authenticated encryption
    pub enc_alg_auth: Option<AuthCryptAlg>,

    /// Algorithm used for anonymous encryption
    pub enc_alg_anon: Option<AnonCryptAlg>,

    /// Algorithm used for message signing
    pub sign_alg: Option<SignAlg>,

    /// If the plaintext has been signed, the JWS is returned for non-repudiation purposes
    pub signed_plaintext: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        did::resolvers::ExampleDIDResolver,
        secrets::resolvers::ExampleSecretsResolver,
        test_vectors::{
            ALICE_AUTH_METHOD_25519, ALICE_AUTH_METHOD_P256, ALICE_AUTH_METHOD_SECPP256K1,
            ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519, BOB_DID, BOB_DID_DOC, BOB_SECRETS,
            BOB_SECRET_KEY_AGREEMENT_KEY_P256_1, BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1, BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
            BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3, ENCRYPTED_MSG_ANON_XC20P_1,
            ENCRYPTED_MSG_ANON_XC20P_2, ENCRYPTED_MSG_AUTH_P256, ENCRYPTED_MSG_AUTH_P256_SIGNED,
            ENCRYPTED_MSG_AUTH_X25519, MESSAGE_ATTACHMENT_BASE64, MESSAGE_ATTACHMENT_JSON,
            MESSAGE_ATTACHMENT_LINKS, MESSAGE_ATTACHMENT_MULTI_1, MESSAGE_ATTACHMENT_MULTI_2,
            MESSAGE_MINIMAL, MESSAGE_SIMPLE, PLAINTEXT_MSG_ATTACHMENT_BASE64,
            PLAINTEXT_MSG_ATTACHMENT_JSON, PLAINTEXT_MSG_ATTACHMENT_LINKS,
            PLAINTEXT_MSG_ATTACHMENT_MULTI_1, PLAINTEXT_MSG_ATTACHMENT_MULTI_2,
            PLAINTEXT_MSG_MINIMAL, PLAINTEXT_MSG_SIMPLE, SIGNED_MSG_ALICE_KEY_1,
            SIGNED_MSG_ALICE_KEY_2, SIGNED_MSG_ALICE_KEY_3,
        },
        PackEncryptedOptions,
    };

    #[tokio::test]
    async fn unpack_works_plaintext() {
        let plaintext_metadata = UnpackMetadata {
            anonymous_sender: false,
            authenticated: false,
            non_repudiation: false,
            encrypted: false,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            signed_plaintext: None,
            re_wrapped_in_forward: false,
        };

        _verify_unpack(PLAINTEXT_MSG_SIMPLE, &MESSAGE_SIMPLE, &plaintext_metadata).await;

        _verify_unpack(PLAINTEXT_MSG_MINIMAL, &MESSAGE_MINIMAL, &plaintext_metadata).await;

        _verify_unpack(
            PLAINTEXT_MSG_ATTACHMENT_BASE64,
            &MESSAGE_ATTACHMENT_BASE64,
            &plaintext_metadata,
        )
        .await;

        _verify_unpack(
            PLAINTEXT_MSG_ATTACHMENT_JSON,
            &MESSAGE_ATTACHMENT_JSON,
            &plaintext_metadata,
        )
        .await;

        _verify_unpack(
            PLAINTEXT_MSG_ATTACHMENT_LINKS,
            &MESSAGE_ATTACHMENT_LINKS,
            &plaintext_metadata,
        )
        .await;

        _verify_unpack(
            PLAINTEXT_MSG_ATTACHMENT_MULTI_1,
            &MESSAGE_ATTACHMENT_MULTI_1,
            &plaintext_metadata,
        )
        .await;

        _verify_unpack(
            PLAINTEXT_MSG_ATTACHMENT_MULTI_2,
            &MESSAGE_ATTACHMENT_MULTI_2,
            &plaintext_metadata,
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_works_plaintext_2way() {
        _unpack_works_plaintext_2way(&MESSAGE_SIMPLE).await;
        _unpack_works_plaintext_2way(&MESSAGE_MINIMAL).await;
        _unpack_works_plaintext_2way(&MESSAGE_ATTACHMENT_BASE64).await;
        _unpack_works_plaintext_2way(&MESSAGE_ATTACHMENT_JSON).await;
        _unpack_works_plaintext_2way(&MESSAGE_ATTACHMENT_LINKS).await;
        _unpack_works_plaintext_2way(&MESSAGE_ATTACHMENT_MULTI_1).await;
        _unpack_works_plaintext_2way(&MESSAGE_ATTACHMENT_MULTI_2).await;

        async fn _unpack_works_plaintext_2way(msg: &Message) {
            let packed = msg.pack_plaintext().expect("Unable pack_plaintext");

            _verify_unpack(
                &packed,
                msg,
                &UnpackMetadata {
                    anonymous_sender: false,
                    authenticated: false,
                    non_repudiation: false,
                    encrypted: false,
                    enc_alg_auth: None,
                    enc_alg_anon: None,
                    sign_alg: None,
                    encrypted_from_kid: None,
                    encrypted_to_kids: None,
                    sign_from: None,
                    signed_plaintext: None,
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unpack_works_signed() {
        let sign_metadata = UnpackMetadata {
            anonymous_sender: false,
            authenticated: false,
            non_repudiation: true,
            encrypted: false,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            signed_plaintext: None,
            re_wrapped_in_forward: false,
        };

        _verify_unpack(
            SIGNED_MSG_ALICE_KEY_1,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                sign_from: Some("did:example:alice#key-1".into()),
                sign_alg: Some(SignAlg::EdDSA),
                signed_plaintext: Some(SIGNED_MSG_ALICE_KEY_1.into()),
                ..sign_metadata.clone()
            },
        )
        .await;

        _verify_unpack(
            SIGNED_MSG_ALICE_KEY_2,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                sign_from: Some("did:example:alice#key-2".into()),
                sign_alg: Some(SignAlg::ES256),
                signed_plaintext: Some(SIGNED_MSG_ALICE_KEY_2.into()),
                ..sign_metadata.clone()
            },
        )
        .await;

        _verify_unpack(
            SIGNED_MSG_ALICE_KEY_3,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                sign_from: Some("did:example:alice#key-3".into()),
                sign_alg: Some(SignAlg::ES256K),
                signed_plaintext: Some(SIGNED_MSG_ALICE_KEY_3.into()),
                ..sign_metadata.clone()
            },
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_works_signed_2way() {
        _unpack_works_signed_2way(
            &MESSAGE_SIMPLE,
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            SignAlg::EdDSA,
        )
        .await;

        _unpack_works_signed_2way(
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            SignAlg::EdDSA,
        )
        .await;

        _unpack_works_signed_2way(
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256.id,
            SignAlg::ES256,
        )
        .await;

        _unpack_works_signed_2way(
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            SignAlg::ES256K,
        )
        .await;

        async fn _unpack_works_signed_2way(
            message: &Message,
            sign_by: &str,
            sign_by_kid: &str,
            sign_alg: SignAlg,
        ) {
            let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (msg, _) = message
                .pack_signed(sign_by, &did_resolver, &secrets_resolver)
                .await
                .expect("Unable pack_signed");

            _verify_unpack(
                &msg,
                &MESSAGE_SIMPLE,
                &UnpackMetadata {
                    sign_from: Some(sign_by_kid.into()),
                    sign_alg: Some(sign_alg),
                    signed_plaintext: Some(msg.clone()),
                    anonymous_sender: false,
                    authenticated: false,
                    non_repudiation: true,
                    encrypted: false,
                    enc_alg_auth: None,
                    enc_alg_anon: None,
                    encrypted_from_kid: None,
                    encrypted_to_kids: None,
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unpack_works_anoncrypt() {
        let metadata = UnpackMetadata {
            anonymous_sender: true,
            authenticated: false,
            non_repudiation: false,
            encrypted: true,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            signed_plaintext: None,
            re_wrapped_in_forward: false,
        };

        _verify_unpack(
            ENCRYPTED_MSG_ANON_XC20P_1,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                enc_alg_anon: Some(AnonCryptAlg::Xc20pEcdhEsA256kw),
                encrypted_to_kids: Some(vec![
                    "did:example:bob#key-x25519-1".into(),
                    "did:example:bob#key-x25519-2".into(),
                    "did:example:bob#key-x25519-3".into(),
                ]),
                ..metadata.clone()
            },
        )
        .await;

        _verify_unpack(
            ENCRYPTED_MSG_ANON_XC20P_2,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                enc_alg_anon: Some(AnonCryptAlg::Xc20pEcdhEsA256kw),
                encrypted_to_kids: Some(vec![
                    "did:example:bob#key-p256-1".into(),
                    "did:example:bob#key-p256-2".into(),
                ]),
                ..metadata.clone()
            },
        )
        .await;

        // TODO: Check P-384 curve support
        // TODO: Check P-521 curve support
    }

    #[tokio::test]
    async fn unpack_works_anoncrypted_2way() {
        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
        )
        .await;

        async fn _unpack_works_anoncrypted_2way(
            msg: &Message,
            to: &str,
            to_kids: &[&str],
            enc_alg: AnonCryptAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (packed, _) = msg
                .pack_encrypted(
                    to,
                    None,
                    None,
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        enc_alg_anon: enc_alg.clone(),
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable pack_encrypted");

            _verify_unpack(
                &packed,
                msg,
                &UnpackMetadata {
                    sign_from: None,
                    sign_alg: None,
                    signed_plaintext: None,
                    anonymous_sender: true,
                    authenticated: false,
                    non_repudiation: false,
                    encrypted: true,
                    enc_alg_auth: None,
                    enc_alg_anon: Some(enc_alg),
                    encrypted_from_kid: None,
                    encrypted_to_kids: Some(to_kids.iter().map(|&k| k.to_owned()).collect()),
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn pack_encrypted_works_anoncrypted_signed() {
        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            SignAlg::ES256,
        )
        .await;

        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            SignAlg::ES256K,
        )
        .await;

        async fn _pack_encrypted_works_anoncrypted_signed(
            msg: &Message,
            to: &str,
            to_kids: &[&str],
            sign_by: &str,
            sign_by_kid: &str,
            enc_alg: AnonCryptAlg,
            sign_alg: SignAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (packed, _) = msg
                .pack_encrypted(
                    to,
                    None,
                    Some(sign_by),
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        enc_alg_anon: enc_alg.clone(),
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable pack_encrypted");

            _verify_unpack_undeterministic(
                &packed,
                msg,
                &UnpackMetadata {
                    sign_from: Some(sign_by_kid.into()),
                    sign_alg: Some(sign_alg),
                    signed_plaintext: None,
                    anonymous_sender: true,
                    authenticated: false,
                    non_repudiation: true,
                    encrypted: true,
                    enc_alg_auth: None,
                    enc_alg_anon: Some(enc_alg),
                    encrypted_from_kid: None,
                    encrypted_to_kids: Some(to_kids.iter().map(|&k| k.to_owned()).collect()),
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unpack_works_authcrypt() {
        let metadata = UnpackMetadata {
            anonymous_sender: false,
            authenticated: true,
            non_repudiation: false,
            encrypted: true,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            signed_plaintext: None,
            re_wrapped_in_forward: false,
        };

        _verify_unpack(
            ENCRYPTED_MSG_AUTH_X25519,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                enc_alg_auth: Some(AuthCryptAlg::A256cbcHs512Ecdh1puA256kw),
                encrypted_from_kid: Some("did:example:alice#key-x25519-1".into()),
                encrypted_to_kids: Some(vec![
                    "did:example:bob#key-x25519-1".into(),
                    "did:example:bob#key-x25519-2".into(),
                    "did:example:bob#key-x25519-3".into(),
                ]),
                ..metadata.clone()
            },
        )
        .await;

        _verify_unpack(
            ENCRYPTED_MSG_AUTH_P256,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                enc_alg_auth: Some(AuthCryptAlg::A256cbcHs512Ecdh1puA256kw),
                encrypted_from_kid: Some("did:example:alice#key-p256-1".into()),
                encrypted_to_kids: Some(vec![
                    "did:example:bob#key-p256-1".into(),
                    "did:example:bob#key-p256-2".into(),
                ]),
                non_repudiation: true,
                sign_from: Some("did:example:alice#key-1".into()),
                sign_alg: Some(SignAlg::EdDSA),
                signed_plaintext: Some(ENCRYPTED_MSG_AUTH_P256_SIGNED.into()),
                ..metadata.clone()
            },
        )
        .await;

        // TODO: Check hidden sender case
        // TODO: Check P-384 curve support
        // TODO: Check P-521 curve support
    }

    #[tokio::test]
    async fn unpack_works_authcrypted_2way() {
        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        async fn _unpack_works_authcrypted_2way(
            msg: &Message,
            to: &str,
            to_kids: &[&str],
            from: &str,
            from_kid: &str,
            enc_alg: AuthCryptAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (packed, _) = msg
                .pack_encrypted(
                    to,
                    Some(from),
                    None,
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable pack_encrypted");

            _verify_unpack(
                &packed,
                msg,
                &UnpackMetadata {
                    sign_from: None,
                    sign_alg: None,
                    signed_plaintext: None,
                    anonymous_sender: false,
                    authenticated: true,
                    non_repudiation: false,
                    encrypted: true,
                    enc_alg_auth: Some(enc_alg),
                    enc_alg_anon: None,
                    encrypted_from_kid: Some(from_kid.into()),
                    encrypted_to_kids: Some(to_kids.iter().map(|&k| k.to_owned()).collect()),
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unpack_works_authcrypted_protected_sender_2way() {
        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        async fn _unpack_works_authcrypted_protected_sender_2way(
            msg: &Message,
            to: &str,
            to_kids: &[&str],
            from: &str,
            from_kid: &str,
            enc_alg_anon: AnonCryptAlg,
            enc_alg_auth: AuthCryptAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (packed, _) = msg
                .pack_encrypted(
                    to,
                    Some(from),
                    None,
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        protect_sender: true,
                        enc_alg_anon: enc_alg_anon.clone(),
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable pack_encrypted");

            _verify_unpack(
                &packed,
                msg,
                &UnpackMetadata {
                    sign_from: None,
                    sign_alg: None,
                    signed_plaintext: None,
                    anonymous_sender: true,
                    authenticated: true,
                    non_repudiation: false,
                    encrypted: true,
                    enc_alg_auth: Some(enc_alg_auth),
                    enc_alg_anon: Some(enc_alg_anon),
                    encrypted_from_kid: Some(from_kid.into()),
                    encrypted_to_kids: Some(to_kids.iter().map(|&k| k.to_owned()).collect()),
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unpack_works_authcrypted_protected_sender_signed_2way() {
        _unpack_works_authcrypted_protected_sender_signed_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::ES256,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_signed_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_signed_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::ES256K,
        )
        .await;

        async fn _unpack_works_authcrypted_protected_sender_signed_2way(
            msg: &Message,
            to: &str,
            to_kids: &[&str],
            from: &str,
            from_kid: &str,
            sign_by: &str,
            sign_by_kid: &str,
            enc_alg_anon: AnonCryptAlg,
            enc_alg_auth: AuthCryptAlg,
            sign_alg: SignAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (packed, _) = msg
                .pack_encrypted(
                    to,
                    Some(from),
                    Some(sign_by),
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        protect_sender: true,
                        enc_alg_anon: enc_alg_anon.clone(),
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable pack_encrypted");

            _verify_unpack_undeterministic(
                &packed,
                msg,
                &UnpackMetadata {
                    sign_from: Some(sign_by_kid.into()),
                    sign_alg: Some(sign_alg),
                    signed_plaintext: Some("nondeterministic".into()),
                    anonymous_sender: true,
                    authenticated: true,
                    non_repudiation: true,
                    encrypted: true,
                    enc_alg_auth: Some(enc_alg_auth),
                    enc_alg_anon: Some(enc_alg_anon),
                    encrypted_from_kid: Some(from_kid.into()),
                    encrypted_to_kids: Some(to_kids.iter().map(|&k| k.to_owned()).collect()),
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unpack_works_authcrypted_signed_2way() {
        _unpack_works_authcrypted_signed_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _unpack_works_authcrypted_signed_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _unpack_works_authcrypted_signed_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::ES256,
        )
        .await;

        _unpack_works_authcrypted_signed_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::ES256K,
        )
        .await;

        async fn _unpack_works_authcrypted_signed_2way(
            msg: &Message,
            to: &str,
            to_kids: &[&str],
            from: &str,
            from_kid: &str,
            sign_by: &str,
            sign_by_kid: &str,
            enc_alg: AuthCryptAlg,
            sign_alg: SignAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (packed, _) = msg
                .pack_encrypted(
                    to,
                    Some(from),
                    Some(sign_by),
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("encrypt is ok.");

            _verify_unpack_undeterministic(
                &packed,
                msg,
                &UnpackMetadata {
                    sign_from: Some(sign_by_kid.into()),
                    sign_alg: Some(sign_alg),
                    signed_plaintext: Some("nondeterministic".into()),
                    anonymous_sender: false,
                    authenticated: true,
                    non_repudiation: true,
                    encrypted: true,
                    enc_alg_auth: Some(enc_alg),
                    enc_alg_anon: None,
                    encrypted_from_kid: Some(from_kid.into()),
                    encrypted_to_kids: Some(to_kids.iter().map(|&k| k.to_owned()).collect()),
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    async fn _verify_unpack(msg: &str, exp_msg: &Message, exp_metadata: &UnpackMetadata) {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

        let (msg, metadata) = Message::unpack(
            msg,
            &did_resolver,
            &secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect("unpack is ok.");

        assert_eq!(&msg, exp_msg);
        assert_eq!(&metadata, exp_metadata);
    }

    // Same as `_verify_unpack`, but skips indeterministic values from metadata checking
    async fn _verify_unpack_undeterministic(
        msg: &str,
        exp_msg: &Message,
        exp_metadata: &UnpackMetadata,
    ) {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

        let (msg, mut metadata) = Message::unpack(
            msg,
            &did_resolver,
            &secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect("unpack is ok.");

        assert_eq!(&msg, exp_msg);

        metadata.signed_plaintext = exp_metadata.signed_plaintext.clone();
        assert_eq!(&metadata, exp_metadata);
    }
}
