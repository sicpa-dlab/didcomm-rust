mod anoncrypt;
mod authcrypt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext},
    protocols::routing::wrap_in_forward_if_needed,
    secrets::SecretsResolver,
    utils::did::{did_or_url, is_did},
    Message, PackSignedMetadata,
};

pub(crate) use self::anoncrypt::anoncrypt;

use self::authcrypt::authcrypt;

impl Message {
    /// Produces `DIDComm Encrypted Message`
    /// https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-message.
    ///
    /// A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) and
    /// hides its content from all but authorized recipients, discloses (optionally) and proves
    /// the sender to exactly and only those recipients, and provides integrity guarantees.
    /// It is important in privacy-preserving routing. It is what normally moves over network
    /// transports in DIDComm applications, and is the safest format for storing DIDComm data at rest.
    ///
    /// Encryption is done as following:
    ///  - Encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
    ///  - if `to` is a DID, then multiplex encryption is done for all keys from the
    ///    receiver's `keyAgreement` verification relationship
    ///    which are compatible the sender's key.
    ///  - if `to` is a key ID, then encryption is done for the receiver's `keyAgreement`
    ///    verification method identified by the given key ID.
    ///  - if `from` is a DID, then sender `keyAgreement` will be negotiated based on recipient preference and
    ///    sender-recipient crypto compatibility.
    ///  - if `from` is a key ID, then the sender's `keyAgreement` verification method
    ///    identified by the given key ID is used.
    ///  - if `from` is None, then anonymous encryption is done and there will be no sender authentication property.
    ///
    /// It's possible to add non-repudiation by providing `sign_by` parameter.
    ///
    /// # Params
    /// - `to` recipient DID or key ID the sender uses encryption.
    /// - `from` a sender DID or key ID. If set message will be repudiable authenticated or anonymous otherwise.
    ///    Must match `from` header in Plaintext if the header is set.
    /// - `sign_by` if `Some` message will be additionally signed to provide additional non-repudiable authentication
    ///    by provided DID/Key. Signed messages are only necessary when the origin of plaintext must be provable
    ///    to third parties, or when the sender can’t be proven to the recipient by authenticated encryption because
    ///    the recipient is not known in advance (e.g., in a broadcast scenario).
    ///    Adding a signature when one is not needed can degrade rather than enhance security because
    ///    it relinquishes the sender’s ability to speak off the record.
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets.
    /// - `options` allow fine configuration of packing process and have implemented `Default`.
    ///
    /// # Returns
    /// Tuple `(encrypted_message, metadata)`.
    /// - `encrypted_message` A DIDComm encrypted message as a JSON string.
    /// - `metadata` additional metadata about this `pack` execution like used keys identifiers,
    ///   used messaging service.
    ///
    /// # Errors
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotResolved` DID doesn't contain mentioned DID Urls (for ex., key id)
    /// - `SecretNotFound` Sender secret is not found.
    /// - `NoCompatibleCrypto` No compatible keys are found between sender and recipient.
    /// - `Unsupported` Used crypto or method is unsupported.
    /// - `InvalidState` Indicates library error.
    /// - `IOError` IO error during DID or secrets resolving
    /// TODO: verify and update errors list
    pub async fn pack_encrypted<'dr, 'sr>(
        &self,
        to: &str,
        from: Option<&str>,
        sign_by: Option<&str>,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &PackEncryptedOptions,
    ) -> Result<(String, PackEncryptedMetadata)> {
        self._validate_pack_encrypted(to, from, sign_by)?;
        // TODO: Think how to avoid resolving of did multiple times
        // and perform async operations in parallel

        // TODO:
        // 1. Extract JWE-related steps to a separate method, so that pack_encrypted uses
        // the extarcted method for JWE steps and wrap_in_forward_if_needed for Routing steps.
        // 2. Make anoncrypt/authcrypt separate non-public modules (not sub-modules), so that
        // both pack_encrypted and Routing implementation use them (to avoid cross dependencies
        // between message::pack_encrypted and protocols::routing modules).

        let (msg, sign_by_kid) = if let Some(sign_by) = sign_by {
            let (msg, PackSignedMetadata { sign_by_kid }) = self
                .pack_signed(sign_by, did_resolver, secrets_resolver)
                .await
                .context("Unable produce sign envelope")?;

            (msg, Some(sign_by_kid))
        } else {
            let msg = self
                .pack_plaintext(did_resolver)
                .await
                .context("Unable produce plaintext")?;
            (msg, None)
        };

        let (msg, from_kid, to_kids) = if let Some(from) = from {
            let (msg, from_kid, to_kids) = authcrypt(
                to,
                from,
                did_resolver,
                secrets_resolver,
                msg.as_bytes(),
                &options.enc_alg_auth,
                &options.enc_alg_anon,
                options.protect_sender,
            )
            .await?;

            (msg, Some(from_kid), to_kids)
        } else {
            let (msg, to_kids) =
                anoncrypt(to, did_resolver, msg.as_bytes(), &options.enc_alg_anon).await?;

            (msg, None, to_kids)
        };

        let (msg, messaging_service) =
            match wrap_in_forward_if_needed(&msg, to, did_resolver, options).await? {
                Some((forward_msg, messaging_service)) => (forward_msg, Some(messaging_service)),
                None => (msg, None),
            };

        let metadata = PackEncryptedMetadata {
            messaging_service,
            from_kid,
            sign_by_kid,
            to_kids,
        };

        Ok((msg, metadata))
    }

    fn _validate_pack_encrypted(
        &self,
        to: &str,
        from: Option<&str>,
        sign_by: Option<&str>,
    ) -> Result<()> {
        if !is_did(to) {
            Err(err_msg(
                ErrorKind::IllegalArgument,
                "`to` value is not a valid DID or DID URL",
            ))?;
        }

        match from {
            Some(from) if !is_did(from) => Err(err_msg(
                ErrorKind::IllegalArgument,
                "`from` value is not a valid DID or DID URL",
            ))?,
            _ => {}
        }

        match sign_by {
            Some(sign_by) if !is_did(sign_by) => Err(err_msg(
                ErrorKind::IllegalArgument,
                "`sign_from` value is not a valid DID or DID URL",
            ))?,
            _ => {}
        }

        let (to_did, _) = did_or_url(to);

        match self.to {
            Some(ref sto) if !sto.contains(&to_did.into()) => {
                Err(err_msg(
                    ErrorKind::IllegalArgument,
                    "`message.to` value does not contain `to` value's DID",
                ))?;
            }
            _ => {}
        }

        match (from, &self.from) {
            (Some(ref from), Some(ref sfrom)) if did_or_url(from).0 != sfrom => Err(err_msg(
                ErrorKind::IllegalArgument,
                "`message.from` value is not equal to `from` value's DID",
            ))?,
            _ => {}
        }

        Ok(())
    }
}

/// Allow fine configuration of packing process.
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct PackEncryptedOptions {
    /// If `true` and message is authenticated than information about sender will be protected from mediators, but
    /// additional re-encryption will be required. For anonymous messages this property will be ignored.
    #[serde(default)]
    pub protect_sender: bool,

    /// Whether the encrypted messages need to be wrapped into `Forward` messages to be sent to Mediators
    /// as defined by the `Forward` protocol.
    #[serde(default = "crate::utils::serde::_true")]
    pub forward: bool,

    /// if forward is enabled these optional headers can be passed to the wrapping `Forward` messages.
    /// If forward is disabled this property will be ignored.
    pub forward_headers: Option<Vec<(String, Value)>>,

    /// Identifier (DID URL) of messaging service (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
    /// If DID doc contains multiple messaging services it allows specify what service to use.
    /// If not present first service will be used.
    pub messaging_service: Option<String>,

    /// Algorithm used for authenticated encryption
    #[serde(default)]
    pub enc_alg_auth: AuthCryptAlg,

    /// Algorithm used for anonymous encryption
    #[serde(default)]
    pub enc_alg_anon: AnonCryptAlg,
}

impl Default for PackEncryptedOptions {
    fn default() -> Self {
        PackEncryptedOptions {
            protect_sender: false,
            forward: true,
            forward_headers: None,
            messaging_service: None,
            enc_alg_auth: AuthCryptAlg::default(),
            enc_alg_anon: AnonCryptAlg::default(),
        }
    }
}

/// Additional metadata about this `encrypt` method execution like used keys identifiers,
/// used messaging service.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct PackEncryptedMetadata {
    /// Information about messaging service used for message preparation.
    /// Practically `service_endpoint` field can be used to transport the message.
    pub messaging_service: Option<MessagingServiceMetadata>,

    /// Identifier (DID URL) of sender key used for message encryption.
    pub from_kid: Option<String>,

    /// Identifier (DID URL) of sender key used for message sign.
    pub sign_by_kid: Option<String>,

    /// Identifiers (DID URLs) of recipient keys used for message encryption.
    pub to_kids: Vec<String>,
}

/// Information about messaging service used for message preparation.
/// Practically `service_endpoint` field can be used to transport the message.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct MessagingServiceMetadata {
    /// Identifier (DID URL) of used messaging service.
    pub id: String,

    /// Service endpoint of used messaging service.
    pub service_endpoint: String,
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, iter::FromIterator};

    use askar_crypto::{
        alg::{
            aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
            chacha20::{Chacha20Key, XC20P},
            ed25519::Ed25519KeyPair,
            k256::K256KeyPair,
            p256::P256KeyPair,
            x25519::X25519KeyPair,
        },
        encrypt::KeyAeadInPlace,
        kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, FromKeyDerivation, KeyExchange},
        repr::{KeyGen, KeySecretBytes},
        sign::KeySigVerify,
    };

    use serde_json::{json, Value};

    use crate::{
        algorithms::AnonCryptAlg,
        did::{resolvers::ExampleDIDResolver, VerificationMaterial, VerificationMethod},
        error::ErrorKind,
        jwe,
        jwk::{FromJwkValue, ToJwkValue},
        jws,
        message::MessagingServiceMetadata,
        protocols::routing::{try_parse_forward, wrap_in_forward},
        secrets::{resolvers::ExampleSecretsResolver, Secret, SecretMaterial},
        test_vectors::{
            ALICE_AUTH_METHOD_25519, ALICE_AUTH_METHOD_P256, ALICE_AUTH_METHOD_SECPP256K1,
            ALICE_DID, ALICE_DID_DOC, ALICE_DID_DOC_WITH_NO_SECRETS, ALICE_SECRETS,
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256, ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            BOB_DID, BOB_DID_COMM_MESSAGING_SERVICE, BOB_DID_DOC, BOB_DID_DOC_NO_SECRETS,
            BOB_SECRETS, BOB_SECRET_KEY_AGREEMENT_KEY_P256_1, BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1, BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
            BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3, BOB_SERVICE, CHARLIE_DID, CHARLIE_DID_DOC,
            CHARLIE_ROTATED_TO_ALICE_SECRETS, CHARLIE_SECRETS, CHARLIE_SECRET_AUTH_KEY_ED25519,
            CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519, CHARLIE_SERVICE, FROM_PRIOR_FULL,
            MEDIATOR1_DID_DOC, MEDIATOR1_SECRETS, MEDIATOR2_DID_DOC, MEDIATOR2_SECRETS,
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
            MEDIATOR3_DID_COMM_MESSAGING_SERVICE, MEDIATOR3_DID_DOC, MEDIATOR3_SECRETS,
            MESSAGE_FROM_PRIOR_FULL, MESSAGE_SIMPLE, PLAINTEXT_MSG_SIMPLE,
        },
        utils::{
            crypto::{JoseKDF, KeyWrap},
            did::did_or_url,
        },
        Message, PackEncryptedMetadata, PackEncryptedOptions, UnpackOptions,
    };

    #[tokio::test]
    async fn pack_encrypted_works_authcrypt() {
        _pack_encrypted_works_authcrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
        )
        .await;

        _pack_encrypted_works_authcrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
        )
        .await;

        _pack_encrypted_works_authcrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
        )
        .await;

        _pack_encrypted_works_authcrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
        )
        .await;

        _pack_encrypted_works_authcrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
        )
        .await;

        _pack_encrypted_works_authcrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
        )
        .await;

        _pack_encrypted_works_authcrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
        )
        .await;

        _pack_encrypted_works_authcrypt::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
        )
        .await;

        async fn _pack_encrypted_works_authcrypt<CE, KDF, KE, KW>(
            to: &str,
            to_keys: Vec<&Secret>,
            from: &str,
            from_key: &VerificationMethod,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
        {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (msg, metadata) = MESSAGE_SIMPLE
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
                .expect("encrypt is ok.");

            assert_eq!(
                metadata,
                PackEncryptedMetadata {
                    messaging_service: None,
                    from_kid: Some(from_key.id.clone()),
                    sign_by_kid: None,
                    to_kids: to_keys.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
                }
            );

            let msg = _verify_authcrypt::<CE, KDF, KE, KW>(&msg, to_keys, from_key);
            _verify_plaintext(&msg, PLAINTEXT_MSG_SIMPLE);
        }
    }

    #[tokio::test]
    async fn pack_encrypted_works_authcrypt_protected_sender() {
        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            AesKey<A256Gcm>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            jwe::EncAlgorithm::A256Gcm,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            jwe::EncAlgorithm::Xc20P,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            AesKey<A256Gcm>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            jwe::EncAlgorithm::A256Gcm,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            Chacha20Key<XC20P>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            jwe::EncAlgorithm::Xc20P,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        async fn _pack_encrypted_works_authcrypt_protected_sender<
            CE,
            KDF,
            KE,
            KW,
            ACE,
            AKDF,
            AKE,
            AKW,
        >(
            to: &str,
            to_keys: Vec<&Secret>,
            from: &str,
            from_key: &VerificationMethod,
            enc_alg_anon: AnonCryptAlg,
            enc_alg_anon_jwe: jwe::EncAlgorithm,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
            ACE: KeyAeadInPlace + KeySecretBytes,
            AKDF: JoseKDF<AKE, AKW>,
            AKE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            AKW: KeyWrap + FromKeyDerivation,
        {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (msg, metadata) = MESSAGE_SIMPLE
                .pack_encrypted(
                    to,
                    Some(from),
                    None,
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        protect_sender: true,
                        enc_alg_anon,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("encrypt is ok.");

            assert_eq!(
                metadata,
                PackEncryptedMetadata {
                    messaging_service: None,
                    from_kid: Some(from_key.id.clone()),
                    sign_by_kid: None,
                    to_kids: to_keys.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
                }
            );

            let msg =
                _verify_anoncrypt::<ACE, AKDF, AKE, AKW>(&msg, to_keys.clone(), enc_alg_anon_jwe);
            let msg = _verify_authcrypt::<CE, KDF, KE, KW>(&msg, to_keys, from_key);
            _verify_plaintext(&msg, PLAINTEXT_MSG_SIMPLE);
        }
    }

    #[tokio::test]
    async fn pack_encrypted_works_authcrypt_protected_sender_signed() {
        _pack_encrypted_works_authcrypt_protected_sender_signed::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            Ed25519KeyPair,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519,
            jws::Algorithm::EdDSA,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender_signed::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            P256KeyPair,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256,
            jws::Algorithm::Es256,
        )
        .await;

        _pack_encrypted_works_authcrypt_protected_sender_signed::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            K256KeyPair,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1,
            jws::Algorithm::Es256K,
        )
        .await;

        async fn _pack_encrypted_works_authcrypt_protected_sender_signed<
            CE,
            KDF,
            KE,
            KW,
            ACE,
            AKDF,
            AKE,
            AKW,
            SK,
        >(
            to: &str,
            to_keys: Vec<&Secret>,
            from: &str,
            from_key: &VerificationMethod,
            enc_alg_anon: AnonCryptAlg,
            enc_alg_anon_jwe: jwe::EncAlgorithm,
            sign_by: &str,
            sign_by_key: &VerificationMethod,
            sign_alg: jws::Algorithm,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
            ACE: KeyAeadInPlace + KeySecretBytes,
            AKDF: JoseKDF<AKE, AKW>,
            AKE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            AKW: KeyWrap + FromKeyDerivation,
            SK: KeySigVerify + FromJwkValue,
        {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (msg, metadata) = MESSAGE_SIMPLE
                .pack_encrypted(
                    to,
                    Some(from),
                    Some(sign_by),
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        protect_sender: true,
                        enc_alg_anon,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("encrypt is ok.");

            assert_eq!(
                metadata,
                PackEncryptedMetadata {
                    messaging_service: None,
                    from_kid: Some(from_key.id.clone()),
                    sign_by_kid: Some(sign_by_key.id.clone()),
                    to_kids: to_keys.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
                }
            );

            let msg =
                _verify_anoncrypt::<ACE, AKDF, AKE, AKW>(&msg, to_keys.clone(), enc_alg_anon_jwe);
            let msg = _verify_authcrypt::<CE, KDF, KE, KW>(&msg, to_keys, from_key);
            let msg = _verify_signed::<SK>(&msg, sign_by_key, sign_alg);
            _verify_plaintext(&msg, PLAINTEXT_MSG_SIMPLE);
        }
    }

    #[tokio::test]
    async fn pack_encrypted_works_authcrypt_sign() {
        _pack_encrypted_works_authcrypt_sign::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            Ed25519KeyPair,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519,
            jws::Algorithm::EdDSA,
        )
        .await;

        _pack_encrypted_works_authcrypt_sign::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            Ed25519KeyPair,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519,
            jws::Algorithm::EdDSA,
        )
        .await;

        _pack_encrypted_works_authcrypt_sign::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            P256KeyPair,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256,
            jws::Algorithm::Es256,
        )
        .await;

        _pack_encrypted_works_authcrypt_sign::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            K256KeyPair,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1,
            jws::Algorithm::Es256K,
        )
        .await;

        async fn _pack_encrypted_works_authcrypt_sign<CE, KDF, KE, KW, SK>(
            to: &str,
            to_keys: Vec<&Secret>,
            from: &str,
            from_key: &VerificationMethod,
            sign_by: &str,
            sign_by_key: &VerificationMethod,
            sign_alg: jws::Algorithm,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
            SK: KeySigVerify + FromJwkValue,
        {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (msg, metadata) = MESSAGE_SIMPLE
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

            assert_eq!(
                metadata,
                PackEncryptedMetadata {
                    messaging_service: None,
                    from_kid: Some(from_key.id.clone()),
                    sign_by_kid: Some(sign_by_key.id.clone()),
                    to_kids: to_keys.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
                }
            );

            let msg = _verify_authcrypt::<CE, KDF, KE, KW>(&msg, to_keys, from_key);
            let msg = _verify_signed::<SK>(&msg, sign_by_key, sign_alg);
            _verify_plaintext(&msg, PLAINTEXT_MSG_SIMPLE);
        }
    }

    #[tokio::test]
    async fn pack_encrypted_works_anoncrypt() {
        _pack_encrypted_works_anoncrypt::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            AesKey<A256Gcm>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            jwe::EncAlgorithm::A256Gcm,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            jwe::EncAlgorithm::Xc20P,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            AesKey<A256Gcm>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            jwe::EncAlgorithm::A256Gcm,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            jwe::EncAlgorithm::Xc20P,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            AesKey<A256Gcm>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            jwe::EncAlgorithm::A256Gcm,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            jwe::EncAlgorithm::Xc20P,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            AesKey<A256Gcm>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            jwe::EncAlgorithm::A256Gcm,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            jwe::EncAlgorithm::Xc20P,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            AesKey<A256Gcm>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            jwe::EncAlgorithm::A256Gcm,
        )
        .await;

        _pack_encrypted_works_anoncrypt::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            jwe::EncAlgorithm::Xc20P,
        )
        .await;

        async fn _pack_encrypted_works_anoncrypt<CE, KDF, KE, KW>(
            to: &str,
            to_keys: Vec<&Secret>,
            enc_alg: AnonCryptAlg,
            enc_alg_jwe: jwe::EncAlgorithm,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
        {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (msg, metadata) = MESSAGE_SIMPLE
                .pack_encrypted(
                    to,
                    None,
                    None,
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        enc_alg_anon: enc_alg,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("encrypt is ok.");

            assert_eq!(
                metadata,
                PackEncryptedMetadata {
                    messaging_service: None,
                    from_kid: None,
                    sign_by_kid: None,
                    to_kids: to_keys.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
                }
            );

            let msg = _verify_anoncrypt::<CE, KDF, KE, KW>(&msg, to_keys, enc_alg_jwe);
            _verify_plaintext(&msg, PLAINTEXT_MSG_SIMPLE);
        }
    }

    #[tokio::test]
    async fn pack_encrypted_works_anoncrypt_sign() {
        _pack_encrypted_works_anoncrypt_sign::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            Ed25519KeyPair,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519,
            jws::Algorithm::EdDSA,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_anoncrypt_sign::<
            AesKey<A256Gcm>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            Ed25519KeyPair,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519,
            jws::Algorithm::EdDSA,
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            jwe::EncAlgorithm::A256Gcm,
        )
        .await;

        _pack_encrypted_works_anoncrypt_sign::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            Ed25519KeyPair,
        >(
            BOB_DID,
            vec![
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            ],
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519,
            jws::Algorithm::EdDSA,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            jwe::EncAlgorithm::Xc20P,
        )
        .await;

        _pack_encrypted_works_anoncrypt_sign::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
            Ed25519KeyPair,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2],
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519,
            jws::Algorithm::EdDSA,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_anoncrypt_sign::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            P256KeyPair,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1],
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256,
            jws::Algorithm::Es256,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        _pack_encrypted_works_anoncrypt_sign::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, P256KeyPair>,
            P256KeyPair,
            AesKey<A256Kw>,
            K256KeyPair,
        >(
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            vec![&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1],
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1,
            jws::Algorithm::Es256K,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            jwe::EncAlgorithm::A256cbcHs512,
        )
        .await;

        async fn _pack_encrypted_works_anoncrypt_sign<CE, KDF, KE, KW, SK>(
            to: &str,
            to_keys: Vec<&Secret>,
            sign_by: &str,
            sign_by_key: &VerificationMethod,
            sign_alg: jws::Algorithm,
            enc_alg: AnonCryptAlg,
            enc_alg_jwe: jwe::EncAlgorithm,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
            KW: KeyWrap + FromKeyDerivation,
            SK: KeySigVerify + FromJwkValue,
        {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (msg, metadata) = MESSAGE_SIMPLE
                .pack_encrypted(
                    to,
                    None,
                    Some(sign_by),
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        enc_alg_anon: enc_alg,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("encrypt is ok.");

            assert_eq!(
                metadata,
                PackEncryptedMetadata {
                    messaging_service: None,
                    from_kid: None,
                    sign_by_kid: Some(sign_by_key.id.clone()),
                    to_kids: to_keys.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
                }
            );

            let msg = _verify_anoncrypt::<CE, KDF, KE, KW>(&msg, to_keys, enc_alg_jwe);
            let msg = _verify_signed::<SK>(&msg, sign_by_key, sign_alg);
            _verify_plaintext(&msg, PLAINTEXT_MSG_SIMPLE);
        }
    }

    #[tokio::test]
    async fn pack_encrypted_works_single_mediator() {
        _pack_encrypted_works_single_mediator(BOB_DID, None, None).await;

        _pack_encrypted_works_single_mediator(BOB_DID, None, Some(ALICE_DID)).await;

        _pack_encrypted_works_single_mediator(BOB_DID, Some(ALICE_DID), None).await;

        _pack_encrypted_works_single_mediator(BOB_DID, Some(ALICE_DID), Some(ALICE_DID)).await;

        _pack_encrypted_works_single_mediator(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            None,
            None,
        )
        .await;

        _pack_encrypted_works_single_mediator(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            None,
            Some(ALICE_DID),
        )
        .await;

        _pack_encrypted_works_single_mediator(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            Some(ALICE_DID),
            None,
        )
        .await;

        _pack_encrypted_works_single_mediator(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            Some(ALICE_DID),
            Some(ALICE_DID),
        )
        .await;

        async fn _pack_encrypted_works_single_mediator(
            to: &str,
            from: Option<&str>,
            sign_by: Option<&str>,
        ) {
            let did_resolver = ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                BOB_DID_DOC.clone(),
                MEDIATOR1_DID_DOC.clone(),
            ]);

            let alice_secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

            let mediator1_secrets_resolver = ExampleSecretsResolver::new(MEDIATOR1_SECRETS.clone());

            let (msg, pack_metadata) = MESSAGE_SIMPLE
                .pack_encrypted(
                    to,
                    from,
                    sign_by,
                    &did_resolver,
                    &alice_secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .expect("Unable encrypt");

            assert_eq!(
                pack_metadata.messaging_service.as_ref(),
                Some(&MessagingServiceMetadata {
                    id: BOB_SERVICE.id.clone(),
                    service_endpoint: BOB_DID_COMM_MESSAGING_SERVICE.service_endpoint.clone(),
                })
            );

            assert_eq!(
                pack_metadata.from_kid.map(|k| did_or_url(&k).0.to_owned()),
                from.map(|d| d.to_owned())
            );
            assert_eq!(
                pack_metadata
                    .sign_by_kid
                    .map(|k| did_or_url(&k).0.to_owned()),
                sign_by.map(|d| d.to_owned())
            );

            match did_or_url(to) {
                (_, Some(to_kid)) => {
                    assert_eq!(
                        pack_metadata
                            .to_kids
                            .iter()
                            .map(|k| k.as_str())
                            .collect::<Vec<_>>(),
                        vec![to_kid]
                    )
                }
                (to_did, None) => {
                    for metadata_to_kid in pack_metadata.to_kids {
                        assert_eq!(did_or_url(&metadata_to_kid).0, to_did);
                    }
                }
            }

            let (unpacked_msg_mediator1, unpack_metadata_mediator1) = Message::unpack(
                &msg,
                &did_resolver,
                &mediator1_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            let forward =
                try_parse_forward(&unpacked_msg_mediator1).expect("Message is not Forward");

            assert_eq!(forward.msg, &unpacked_msg_mediator1);
            assert_eq!(&forward.next, to);

            assert!(unpack_metadata_mediator1.encrypted);
            assert!(!unpack_metadata_mediator1.authenticated);
            assert!(!unpack_metadata_mediator1.non_repudiation);
            assert!(unpack_metadata_mediator1.anonymous_sender);
            assert!(!unpack_metadata_mediator1.re_wrapped_in_forward);

            let forwarded_msg = serde_json::to_string(&forward.forwarded_msg)
                .expect("Unable serialize forwarded message");

            let (unpacked_msg, unpack_metadata) = Message::unpack(
                &forwarded_msg,
                &did_resolver,
                &bob_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            assert_eq!(&unpacked_msg, &*MESSAGE_SIMPLE);

            assert!(unpack_metadata.encrypted);
            assert_eq!(
                unpack_metadata.authenticated,
                from.is_some() || sign_by.is_some()
            );
            assert_eq!(unpack_metadata.non_repudiation, sign_by.is_some());
            assert_eq!(unpack_metadata.anonymous_sender, from.is_none());
            assert!(!unpack_metadata.re_wrapped_in_forward);
        }
    }

    #[tokio::test]
    async fn pack_encrypted_works_multiple_mediators_alternative_endpoints() {
        _pack_encrypted_works_multiple_mediators_alternative_endpoints(CHARLIE_DID, None, None)
            .await;

        _pack_encrypted_works_multiple_mediators_alternative_endpoints(
            CHARLIE_DID,
            None,
            Some(ALICE_DID),
        )
        .await;

        _pack_encrypted_works_multiple_mediators_alternative_endpoints(
            CHARLIE_DID,
            Some(ALICE_DID),
            None,
        )
        .await;

        _pack_encrypted_works_multiple_mediators_alternative_endpoints(
            CHARLIE_DID,
            Some(ALICE_DID),
            Some(ALICE_DID),
        )
        .await;

        _pack_encrypted_works_multiple_mediators_alternative_endpoints(
            &CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519.id,
            None,
            None,
        )
        .await;

        _pack_encrypted_works_multiple_mediators_alternative_endpoints(
            &CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519.id,
            None,
            Some(ALICE_DID),
        )
        .await;

        _pack_encrypted_works_multiple_mediators_alternative_endpoints(
            &CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519.id,
            Some(ALICE_DID),
            None,
        )
        .await;

        _pack_encrypted_works_multiple_mediators_alternative_endpoints(
            &CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519.id,
            Some(ALICE_DID),
            Some(ALICE_DID),
        )
        .await;

        async fn _pack_encrypted_works_multiple_mediators_alternative_endpoints(
            to: &str,
            from: Option<&str>,
            sign_by: Option<&str>,
        ) {
            let msg = Message::build(
                "1234567890".to_owned(),
                "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
                json!({"messagespecificattribute": "and its value"}),
            )
            .from(ALICE_DID.to_owned())
            .to(CHARLIE_DID.to_owned())
            .created_time(1516269022)
            .expires_time(1516385931)
            .finalize();

            let did_resolver = ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                CHARLIE_DID_DOC.clone(),
                MEDIATOR1_DID_DOC.clone(),
                MEDIATOR2_DID_DOC.clone(),
                MEDIATOR3_DID_DOC.clone(),
            ]);

            let alice_secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let charlie_secrets_resolver = ExampleSecretsResolver::new(CHARLIE_SECRETS.clone());

            let mediator1_secrets_resolver = ExampleSecretsResolver::new(MEDIATOR1_SECRETS.clone());

            let mediator2_secrets_resolver = ExampleSecretsResolver::new(MEDIATOR2_SECRETS.clone());

            let mediator3_secrets_resolver = ExampleSecretsResolver::new(MEDIATOR3_SECRETS.clone());

            let (packed_msg, pack_metadata) = msg
                .pack_encrypted(
                    to,
                    from,
                    sign_by,
                    &did_resolver,
                    &alice_secrets_resolver,
                    &PackEncryptedOptions {
                        forward_headers: Some(vec![
                            ("example-header-1".into(), json!("example-header-1-value")),
                            ("example-header-2".into(), json!("example-header-2-value")),
                        ]),
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable encrypt");

            assert_eq!(
                pack_metadata.messaging_service.as_ref(),
                Some(&MessagingServiceMetadata {
                    id: CHARLIE_SERVICE.id.clone(),
                    service_endpoint: MEDIATOR3_DID_COMM_MESSAGING_SERVICE
                        .service_endpoint
                        .clone(),
                })
            );

            assert_eq!(
                pack_metadata.from_kid.map(|k| did_or_url(&k).0.to_owned()),
                from.map(|d| d.to_owned())
            );
            assert_eq!(
                pack_metadata
                    .sign_by_kid
                    .map(|k| did_or_url(&k).0.to_owned()),
                sign_by.map(|d| d.to_owned())
            );

            match did_or_url(to) {
                (_, Some(to_kid)) => {
                    assert_eq!(
                        pack_metadata
                            .to_kids
                            .iter()
                            .map(|k| k.as_str())
                            .collect::<Vec<_>>(),
                        vec![to_kid]
                    )
                }
                (to_did, None) => {
                    for metadata_to_kid in pack_metadata.to_kids {
                        assert_eq!(did_or_url(&metadata_to_kid).0, to_did);
                    }
                }
            }

            let (unpacked_msg_mediator3, unpack_metadata_mediator3) = Message::unpack(
                &packed_msg,
                &did_resolver,
                &mediator3_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            let forward_at_mediator3 =
                try_parse_forward(&unpacked_msg_mediator3).expect("Message is not Forward");

            assert_eq!(forward_at_mediator3.msg, &unpacked_msg_mediator3);

            assert_eq!(
                &forward_at_mediator3.msg.extra_headers,
                &HashMap::from_iter([
                    ("example-header-1".into(), json!("example-header-1-value")),
                    ("example-header-2".into(), json!("example-header-2-value")),
                ])
            );

            assert_eq!(
                &forward_at_mediator3.next,
                "did:example:mediator2#key-x25519-1"
            );

            assert!(unpack_metadata_mediator3.encrypted);
            assert!(!unpack_metadata_mediator3.authenticated);
            assert!(!unpack_metadata_mediator3.non_repudiation);
            assert!(unpack_metadata_mediator3.anonymous_sender);
            assert!(!unpack_metadata_mediator3.re_wrapped_in_forward);

            let forwarded_msg_at_mediator3 =
                serde_json::to_string(&forward_at_mediator3.forwarded_msg)
                    .expect("Unable serialize forwarded message");

            let (unpacked_msg_mediator2, unpack_metadata_mediator2) = Message::unpack(
                &forwarded_msg_at_mediator3,
                &did_resolver,
                &mediator2_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            let forward_at_mediator2 =
                try_parse_forward(&unpacked_msg_mediator2).expect("Message is not Forward");

            assert_eq!(forward_at_mediator2.msg, &unpacked_msg_mediator2);

            assert_eq!(
                &forward_at_mediator2.msg.extra_headers,
                &HashMap::from_iter([
                    ("example-header-1".into(), json!("example-header-1-value")),
                    ("example-header-2".into(), json!("example-header-2-value")),
                ])
            );

            assert_eq!(
                &forward_at_mediator2.next,
                "did:example:mediator1#key-x25519-1"
            );

            assert!(unpack_metadata_mediator2.encrypted);
            assert!(!unpack_metadata_mediator2.authenticated);
            assert!(!unpack_metadata_mediator2.non_repudiation);
            assert!(unpack_metadata_mediator2.anonymous_sender);
            assert!(!unpack_metadata_mediator2.re_wrapped_in_forward);

            let forwarded_msg_at_mediator2 =
                serde_json::to_string(&forward_at_mediator2.forwarded_msg)
                    .expect("Unable serialize forwarded message");

            let (unpacked_msg_mediator1, unpack_metadata_mediator1) = Message::unpack(
                &forwarded_msg_at_mediator2,
                &did_resolver,
                &mediator1_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            let forward_at_mediator1 =
                try_parse_forward(&unpacked_msg_mediator1).expect("Message is not Forward");

            assert_eq!(forward_at_mediator1.msg, &unpacked_msg_mediator1);

            assert_eq!(
                &forward_at_mediator1.msg.extra_headers,
                &HashMap::from_iter([
                    ("example-header-1".into(), json!("example-header-1-value")),
                    ("example-header-2".into(), json!("example-header-2-value")),
                ])
            );

            assert_eq!(&forward_at_mediator1.next, to);

            assert!(unpack_metadata_mediator1.encrypted);
            assert!(!unpack_metadata_mediator1.authenticated);
            assert!(!unpack_metadata_mediator1.non_repudiation);
            assert!(unpack_metadata_mediator1.anonymous_sender);
            assert!(!unpack_metadata_mediator1.re_wrapped_in_forward);

            let forwarded_msg_at_mediator1 =
                serde_json::to_string(&forward_at_mediator1.forwarded_msg)
                    .expect("Unable serialize forwarded message");

            let (unpacked_msg, unpack_metadata) = Message::unpack(
                &forwarded_msg_at_mediator1,
                &did_resolver,
                &charlie_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            assert_eq!(&unpacked_msg, &msg);

            assert!(unpack_metadata.encrypted);
            assert_eq!(
                unpack_metadata.authenticated,
                from.is_some() || sign_by.is_some()
            );
            assert_eq!(unpack_metadata.non_repudiation, sign_by.is_some());
            assert_eq!(unpack_metadata.anonymous_sender, from.is_none());
            assert!(!unpack_metadata.re_wrapped_in_forward);
        }
    }

    #[tokio::test]
    async fn wrap_in_forward_works_mediator_unknown_by_sender() {
        _wrap_in_forward_works_mediator_unknown_by_sender(BOB_DID, None, None).await;

        _wrap_in_forward_works_mediator_unknown_by_sender(BOB_DID, None, Some(ALICE_DID)).await;

        _wrap_in_forward_works_mediator_unknown_by_sender(BOB_DID, Some(ALICE_DID), None).await;

        _wrap_in_forward_works_mediator_unknown_by_sender(
            BOB_DID,
            Some(ALICE_DID),
            Some(ALICE_DID),
        )
        .await;

        _wrap_in_forward_works_mediator_unknown_by_sender(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            None,
            None,
        )
        .await;

        _wrap_in_forward_works_mediator_unknown_by_sender(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            None,
            Some(ALICE_DID),
        )
        .await;

        _wrap_in_forward_works_mediator_unknown_by_sender(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            Some(ALICE_DID),
            None,
        )
        .await;

        _wrap_in_forward_works_mediator_unknown_by_sender(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            Some(ALICE_DID),
            Some(ALICE_DID),
        )
        .await;

        async fn _wrap_in_forward_works_mediator_unknown_by_sender(
            to: &str,
            from: Option<&str>,
            sign_by: Option<&str>,
        ) {
            let did_resolver = ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                BOB_DID_DOC.clone(),
                MEDIATOR1_DID_DOC.clone(),
                MEDIATOR2_DID_DOC.clone(),
            ]);

            let alice_secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

            let mediator1_secrets_resolver = ExampleSecretsResolver::new(MEDIATOR1_SECRETS.clone());

            let mediator2_secrets_resolver = ExampleSecretsResolver::new(MEDIATOR2_SECRETS.clone());

            let (msg, pack_metadata) = MESSAGE_SIMPLE
                .pack_encrypted(
                    to,
                    from,
                    sign_by,
                    &did_resolver,
                    &alice_secrets_resolver,
                    &PackEncryptedOptions {
                        messaging_service: Some(BOB_SERVICE.id.clone()),
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable encrypt");

            assert_eq!(
                pack_metadata.messaging_service.as_ref(),
                Some(&MessagingServiceMetadata {
                    id: BOB_SERVICE.id.clone(),
                    service_endpoint: BOB_DID_COMM_MESSAGING_SERVICE.service_endpoint.clone(),
                })
            );

            let (unpacked_msg_mediator1, unpack_metadata_mediator1) = Message::unpack(
                &msg,
                &did_resolver,
                &mediator1_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            let forward_at_mediator1 =
                try_parse_forward(&unpacked_msg_mediator1).expect("Message is not Forward");

            assert_eq!(forward_at_mediator1.msg, &unpacked_msg_mediator1);
            assert_eq!(&forward_at_mediator1.next, to);

            assert!(unpack_metadata_mediator1.encrypted);
            assert!(!unpack_metadata_mediator1.authenticated);
            assert!(!unpack_metadata_mediator1.non_repudiation);
            assert!(unpack_metadata_mediator1.anonymous_sender);
            assert!(!unpack_metadata_mediator1.re_wrapped_in_forward);

            let forwarded_msg_at_mediator1 =
                serde_json::to_string(&forward_at_mediator1.forwarded_msg)
                    .expect("Unable serialize forwarded message");

            let forward_msg_for_mediator2 = wrap_in_forward(
                &forwarded_msg_at_mediator1,
                None,
                &forward_at_mediator1.next,
                &vec![MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1.id.clone()],
                &AnonCryptAlg::default(),
                &did_resolver,
            )
            .await
            .expect("Unable wrap in forward");

            let (unpacked_msg_mediator2, unpack_metadata_mediator2) = Message::unpack(
                &forward_msg_for_mediator2,
                &did_resolver,
                &mediator2_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            let forward_at_mediator2 =
                try_parse_forward(&unpacked_msg_mediator2).expect("Message is not Forward");

            assert_eq!(forward_at_mediator2.msg, &unpacked_msg_mediator2);
            assert_eq!(&forward_at_mediator2.next, to);

            assert!(unpack_metadata_mediator2.encrypted);
            assert!(!unpack_metadata_mediator2.authenticated);
            assert!(!unpack_metadata_mediator2.non_repudiation);
            assert!(unpack_metadata_mediator2.anonymous_sender);
            assert!(!unpack_metadata_mediator2.re_wrapped_in_forward);

            let forwarded_msg_at_mediator2 =
                serde_json::to_string(&forward_at_mediator2.forwarded_msg)
                    .expect("Unable serialize forwarded message");

            let (unpacked_msg, unpack_metadata) = Message::unpack(
                &forwarded_msg_at_mediator2,
                &did_resolver,
                &bob_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            assert_eq!(&unpacked_msg, &*MESSAGE_SIMPLE);

            assert!(unpack_metadata.encrypted);
            assert_eq!(
                unpack_metadata.authenticated,
                from.is_some() || sign_by.is_some()
            );
            assert_eq!(unpack_metadata.non_repudiation, sign_by.is_some());
            assert_eq!(unpack_metadata.anonymous_sender, from.is_none());
            assert!(!unpack_metadata.re_wrapped_in_forward);
        }
    }

    // TODO: Add negative tests for Routing protocol

    #[tokio::test]
    async fn pack_encrypted_works_from_not_did_or_did_url() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let res = MESSAGE_SIMPLE
            .pack_encrypted(
                BOB_DID,
                "not-a-did".into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::IllegalArgument);

        assert_eq!(
            format!("{}", err),
            "Illegal argument: `from` value is not a valid DID or DID URL"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_to_not_did_or_did_url() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let res = MESSAGE_SIMPLE
            .pack_encrypted(
                "not-a-did".into(),
                None,
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::IllegalArgument);

        assert_eq!(
            format!("{}", err),
            "Illegal argument: `to` value is not a valid DID or DID URL"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_sign_by_not_did_or_did_url() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let res = MESSAGE_SIMPLE
            .pack_encrypted(
                BOB_DID,
                ALICE_DID.into(),
                "not-a-did".into(),
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::IllegalArgument);

        assert_eq!(
            format!("{}", err),
            "Illegal argument: `sign_from` value is not a valid DID or DID URL"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_from_differs_msg_from() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let mut msg = MESSAGE_SIMPLE.clone();
        msg.from = CHARLIE_DID.to_string().into();
        let res = msg
            .pack_encrypted(
                BOB_DID,
                ALICE_DID.into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::IllegalArgument);

        assert_eq!(
            format!("{}", err),
            "Illegal argument: `message.from` value is not equal to `from` value's DID"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_to_differs_msg_to() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let mut msg = MESSAGE_SIMPLE.clone();
        msg.to = Some(vec![CHARLIE_DID.to_string()]);
        let res = msg
            .pack_encrypted(
                BOB_DID,
                ALICE_DID.into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::IllegalArgument);

        assert_eq!(
            format!("{}", err),
            "Illegal argument: `message.to` value does not contain `to` value's DID"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_to_presented_in_msg_to() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let mut msg = MESSAGE_SIMPLE.clone();
        msg.to = Some(vec![CHARLIE_DID.to_string(), BOB_DID.to_string()]);
        let _ = msg
            .pack_encrypted(
                BOB_DID,
                ALICE_DID.into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;
    }

    #[tokio::test]
    async fn pack_encrypted_works_from_not_did_or_did_url_in_msg() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let mut msg = MESSAGE_SIMPLE.clone();
        msg.from = "not-a-did".to_string().into();
        let res = msg
            .pack_encrypted(
                BOB_DID,
                "not-a-did".into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::IllegalArgument);

        assert_eq!(
            format!("{}", err),
            "Illegal argument: `from` value is not a valid DID or DID URL"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_to_not_did_or_did_url_in_msg() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let mut msg = MESSAGE_SIMPLE.clone();
        msg.to = Some(vec!["not-a-did".to_string()]);
        let res = msg
            .pack_encrypted(
                "not-a-did".into(),
                ALICE_DID.into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::IllegalArgument);

        assert_eq!(
            format!("{}", err),
            "Illegal argument: `to` value is not a valid DID or DID URL"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_from_did_url_from_msg_did_positive() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let _ = MESSAGE_SIMPLE
            .pack_encrypted(
                BOB_DID,
                "did:example:alice#key-x25519-1".into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;
    }

    #[tokio::test]
    async fn pack_encrypted_works_to_did_url_to_msg_did_positive() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let mut msg = MESSAGE_SIMPLE.clone();
        msg.to = Some(vec![ALICE_DID.to_string(), BOB_DID.to_string()]);
        let _ = msg
            .pack_encrypted(
                "did:example:bob#key-x25519-1".into(),
                None,
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;
    }

    #[tokio::test]
    async fn pack_encrypted_works_sign_by_differs_msg_from_positive() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let _ = MESSAGE_SIMPLE
            .pack_encrypted(
                BOB_DID,
                ALICE_DID.into(),
                CHARLIE_DID.into(),
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;
    }

    #[tokio::test]
    async fn pack_encrypted_works_from_did_from_msg_did_url() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let mut msg = MESSAGE_SIMPLE.clone();
        msg.from = "did:example:alice#key-x25519-1".to_string().into();

        let res = msg
            .pack_encrypted(
                BOB_DID,
                ALICE_DID.into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::IllegalArgument);

        assert_eq!(
            format!("{}", err),
            "Illegal argument: `message.from` value is not equal to `from` value's DID"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_to_did_to_msg_did_url() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let mut msg = MESSAGE_SIMPLE.clone();
        msg.to = Some(vec!["did:example:bob#key-x25519-1".into()]);
        let res = msg
            .pack_encrypted(
                BOB_DID,
                None,
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::IllegalArgument);

        assert_eq!(
            format!("{}", err),
            "Illegal argument: `message.to` value does not contain `to` value's DID"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_from_unknown_did() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let mut msg = MESSAGE_SIMPLE.clone();
        msg.from = "did:example:unknown".to_string().into();
        let res = msg
            .pack_encrypted(
                BOB_DID,
                "did:example:unknown".into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::DIDNotResolved);

        assert_eq!(format!("{}", err), "DID not resolved: Sender did not found");
    }

    #[tokio::test]
    async fn pack_encrypted_works_from_unknown_did_url() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let from = ALICE_DID.to_string() + "#unknown-key";
        let res = MESSAGE_SIMPLE
            .pack_encrypted(
                BOB_DID,
                from.as_str().into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::DIDUrlNotFound);

        assert_eq!(
            format!("{}", err),
            "DID URL not found: No sender key agreements found"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_to_unknown_did() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let mut msg = MESSAGE_SIMPLE.clone();
        msg.to = Some(vec!["did:example:unknown".into()]);
        let res = msg
            .pack_encrypted(
                "did:example:unknown",
                None,
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::DIDNotResolved);

        assert_eq!(
            format!("{}", err),
            "DID not resolved: Recipient did not found"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_to_unknown_did_url() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let to = BOB_DID.to_string() + "#unknown-key";
        let res = MESSAGE_SIMPLE
            .pack_encrypted(
                to.as_str(),
                ALICE_DID.into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::DIDUrlNotFound);

        assert_eq!(
            format!("{}", err),
            "DID URL not found: No recipient key agreements found"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_sign_by_unknown_did_url() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let sign_by = ALICE_DID.to_string() + "#unknown-key";
        let res = MESSAGE_SIMPLE
            .pack_encrypted(
                BOB_DID,
                ALICE_DID.into(),
                sign_by.as_str().into(),
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::DIDUrlNotFound);

        assert_eq!(
            format!("{}", err),
            "DID URL not found: Unable produce sign envelope: Signer key id not found in did doc"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_from_not_in_secrets() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let res = MESSAGE_SIMPLE
            .pack_encrypted(
                BOB_DID,
                "did:example:alice#key-x25519-not-in-secrets-1".into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::SecretNotFound);

        assert_eq!(
            format!("{}", err),
            "Secret not found: No sender secrets found"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_sign_by_not_in_secrets() {
        let did_resolver = ExampleDIDResolver::new(vec![
            ALICE_DID_DOC_WITH_NO_SECRETS.clone(),
            BOB_DID_DOC.clone(),
        ]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let res = MESSAGE_SIMPLE
            .pack_encrypted(
                BOB_DID,
                ALICE_DID.into(),
                "did:example:alice#key-not-in-secrets-1".into(),
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::SecretNotFound);

        assert_eq!(
            format!("{}", err),
            "Secret not found: Unable produce sign envelope: No signer secrets found"
        );
    }

    #[tokio::test]
    async fn pack_encrypted_works_to_not_in_secrets_positive() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC_NO_SECRETS.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let to = "did:example:bob#key-x25519-not-secrets-1";
        let _ = MESSAGE_SIMPLE
            .pack_encrypted(
                to,
                ALICE_DID.into(),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await;
    }

    #[tokio::test]
    async fn pack_encrypted_works_to_from_different_curves() {
        _pack_encrypted_works_to_from_different_curves(
            "did:example:alice#key-x25519-1".into(),
            "did:example:bob#key-p256-1",
        )
        .await;
        _pack_encrypted_works_to_from_different_curves(
            "did:example:alice#key-x25519-1".into(),
            "did:example:bob#key-p384-1",
        )
        .await;
        _pack_encrypted_works_to_from_different_curves(
            "did:example:alice#key-x25519-1".into(),
            "did:example:bob#key-p521-1",
        )
        .await;
        _pack_encrypted_works_to_from_different_curves(
            "did:example:alice#key-p256-1".into(),
            "did:example:bob#key-p384-1",
        )
        .await;
        _pack_encrypted_works_to_from_different_curves(
            "did:example:alice#key-p256-1".into(),
            "did:example:bob#key-p521-1",
        )
        .await;
        _pack_encrypted_works_to_from_different_curves(
            "did:example:alice#key-p521-1".into(),
            "did:example:bob#key-p384-1",
        )
        .await;

        async fn _pack_encrypted_works_to_from_different_curves(from: Option<&str>, to: &str) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let res = MESSAGE_SIMPLE
                .pack_encrypted(
                    to,
                    from,
                    None,
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await;

            let err = res.expect_err("res is ok");
            assert_eq!(err.kind(), ErrorKind::NoCompatibleCrypto);

            assert_eq!(
                format!("{}", err),
                "No compatible crypto: No common keys between sender and recipient found"
            );
        }
    }

    #[tokio::test]
    async fn pack_encrypted_works_from_prior() {
        let did_resolver = ExampleDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
            CHARLIE_DID_DOC.clone(),
        ]);
        let charlie_rotated_to_alice_secrets_resolver =
            ExampleSecretsResolver::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());
        let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

        let (packed_msg, _pack_metadata) = MESSAGE_FROM_PRIOR_FULL
            .pack_encrypted(
                BOB_DID,
                Some(ALICE_DID),
                None,
                &did_resolver,
                &charlie_rotated_to_alice_secrets_resolver,
                &&PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await
            .expect("Unable pack_encrypted");

        let (unpacked_msg, unpack_metadata) = Message::unpack(
            &packed_msg,
            &did_resolver,
            &bob_secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect("Unable unpack");

        assert_eq!(&unpacked_msg, &*MESSAGE_FROM_PRIOR_FULL);
        assert_eq!(
            unpack_metadata.from_prior_issuer_kid.as_ref(),
            Some(&CHARLIE_SECRET_AUTH_KEY_ED25519.id)
        );
        assert_eq!(unpack_metadata.from_prior.as_ref(), Some(&*FROM_PRIOR_FULL));
    }

    fn _verify_authcrypt<CE, KDF, KE, KW>(
        msg: &str,
        to_keys: Vec<&Secret>,
        from_key: &VerificationMethod,
    ) -> String
    where
        CE: KeyAeadInPlace + KeySecretBytes,
        KDF: JoseKDF<KE, KW>,
        KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
        KW: KeyWrap + FromKeyDerivation,
    {
        let mut buf = vec![];
        let msg = jwe::parse(msg, &mut buf).expect("Unable parse jwe");

        assert_eq!(
            msg.jwe
                .recipients
                .iter()
                .map(|r| r.header.kid)
                .collect::<Vec<_>>(),
            to_keys.iter().map(|s| s.id.clone()).collect::<Vec<_>>()
        );

        assert_eq!(
            msg.protected.typ,
            Some("application/didcomm-encrypted+json")
        );

        assert_eq!(msg.protected.alg, jwe::Algorithm::Ecdh1puA256kw);
        assert_eq!(msg.protected.enc, jwe::EncAlgorithm::A256cbcHs512);
        assert_eq!(msg.protected.skid, Some(from_key.id.as_ref()));

        let mut common_msg: Option<Vec<u8>> = None;

        for to_key in to_keys {
            let from_kid = &from_key.id;
            let to_kid = &to_key.id;

            let from_key = match from_key.verification_material {
                VerificationMaterial::JWK(ref jwk) => {
                    KE::from_jwk_value(jwk).expect("Unable from_jwk_value")
                }
                _ => panic!("Unexpected verification method"),
            };

            let to_key = match to_key.secret_material {
                SecretMaterial::JWK(ref jwk) => {
                    KE::from_jwk_value(jwk).expect("Unable from_jwk_value")
                }
                _ => panic!("Unexpected verification method"),
            };

            let msg = msg
                .decrypt::<CE, KDF, KE, KW>(Some((from_kid, &from_key)), (to_kid, &to_key))
                .expect("Unable decrypt msg");

            common_msg = if let Some(ref res) = common_msg {
                assert_eq!(res, &msg);
                Some(msg)
            } else {
                Some(msg)
            };
        }

        let msg = common_msg.expect("No result gotten");
        String::from_utf8(msg).expect("Unable from_utf8")
    }

    fn _verify_anoncrypt<CE, KDF, KE, KW>(
        msg: &str,
        to_keys: Vec<&Secret>,
        enc_alg: jwe::EncAlgorithm,
    ) -> String
    where
        CE: KeyAeadInPlace + KeySecretBytes,
        KDF: JoseKDF<KE, KW>,
        KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
        KW: KeyWrap + FromKeyDerivation,
    {
        let mut buf = vec![];
        let msg = jwe::parse(msg, &mut buf).expect("Unable parse jwe");

        assert_eq!(
            msg.jwe
                .recipients
                .iter()
                .map(|r| r.header.kid)
                .collect::<Vec<_>>(),
            to_keys.iter().map(|s| s.id.clone()).collect::<Vec<_>>()
        );

        assert_eq!(
            msg.protected.typ,
            Some("application/didcomm-encrypted+json")
        );

        assert_eq!(msg.protected.alg, jwe::Algorithm::EcdhEsA256kw);
        assert_eq!(msg.protected.enc, enc_alg);
        assert_eq!(msg.protected.skid, None);

        let mut common_msg: Option<Vec<u8>> = None;

        for to_key in to_keys {
            let to_kid = &to_key.id;

            let to_key = match to_key.secret_material {
                SecretMaterial::JWK(ref jwk) => {
                    KE::from_jwk_value(jwk).expect("Unable from_jwk_value")
                }
                _ => panic!("Unexpected verification method"),
            };

            let msg = msg
                .decrypt::<CE, KDF, KE, KW>(None, (to_kid, &to_key))
                .expect("Unable decrypt msg");

            common_msg = if let Some(ref res) = common_msg {
                assert_eq!(res, &msg);
                Some(msg)
            } else {
                Some(msg)
            };
        }

        let msg = common_msg.expect("No result gotten");
        String::from_utf8(msg).expect("Unable from_utf8")
    }

    fn _verify_signed<Key: KeySigVerify + FromJwkValue>(
        msg: &str,
        sign_key: &VerificationMethod,
        alg: jws::Algorithm,
    ) -> String {
        let mut buf = vec![];
        let msg = jws::parse(&msg, &mut buf).expect("Unable parse");

        assert_eq!(
            msg.protected,
            vec![jws::ProtectedHeader {
                typ: "application/didcomm-signed+json",
                alg,
            }]
        );

        assert_eq!(msg.jws.signatures.len(), 1);

        assert_eq!(
            msg.jws.signatures[0].header,
            jws::Header { kid: &sign_key.id }
        );

        let sign_key_id = &sign_key.id;

        let sign_key = match sign_key.verification_material {
            VerificationMaterial::JWK(ref jwk) => {
                Key::from_jwk_value(jwk).expect("Unable from_jwk_value")
            }
            _ => panic!("Unexpected verification_material"),
        };

        let valid = msg.verify((sign_key_id, &sign_key)).expect("Unable verify");
        assert!(valid);

        let payload = base64::decode_config(msg.jws.payload, base64::URL_SAFE_NO_PAD)
            .expect("Unable decode_config");

        String::from_utf8(payload).expect("Unable from_utf8")
    }

    fn _verify_plaintext(msg: &str, exp_msg: &str) {
        let msg: Value = serde_json::from_str(msg).expect("Unable from_str");
        let exp_msg: Value = serde_json::from_str(exp_msg).expect("Unable from_str");
        assert_eq!(msg, exp_msg)
    }
}
