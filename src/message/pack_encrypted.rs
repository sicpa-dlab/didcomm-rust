use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs},
};
use serde_json::Value;

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext},
    jwe,
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyAlg},
        did::did_or_url,
    },
    Message, PackSignedMetadata,
};

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
        // TODO: Support `forward` protocol wrapping
        if options.forward {
            Err(err_msg(
                ErrorKind::Unsupported,
                "Forward protocol wrapping is unsupported in this version",
            ))?
        };

        // TODO: Think how to avoid resolving of did multiple times
        // and perform async operations in parallel

        let (msg, sign_by_kid) = if let Some(sign_by) = sign_by {
            let (msg, PackSignedMetadata { sign_by_kid }) = self
                .pack_signed(sign_by, did_resolver, secrets_resolver)
                .await
                .context("Unable produce sign envelope")?;

            (msg, Some(sign_by_kid))
        } else {
            let msg = self.pack_plaintext().context("Unable produce plaintext")?;
            (msg, None)
        };

        let (msg, from_kid, to_kids) = if let Some(from) = from {
            let (msg, from_kid, to_kids) = Self::_authcrypt(
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
                Self::_anoncrypt(to, did_resolver, msg.as_bytes(), &options.enc_alg_anon).await?;
            (msg, None, to_kids)
        };

        let metadata = PackEncryptedMetadata {
            messaging_service: None,
            from_kid,
            sign_by_kid,
            to_kids,
        };

        Ok((msg, metadata))
    }

    async fn _authcrypt<'dr, 'sr>(
        to: &str,
        from: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        msg: &[u8],
        enc_alg_auth: &AuthCryptAlg,
        enc_alg_anon: &AnonCryptAlg,
        protect_sender: bool,
    ) -> Result<(String, String, Vec<String>)> /* (msg, from_kid, to_kids) */ {
        let (to_did, to_kid) = did_or_url(to);

        let to_ddoc = did_resolver
            .resolve(to_did)
            .await
            .context("Unable resolve recepient did")?
            .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Recepient did not found"))?;

        let (from_did, from_kid) = did_or_url(from);

        let from_ddoc = did_resolver
            .resolve(from_did)
            .await
            .context("Unable resolve sender did")?
            .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Sender did not found"))?;

        // Initial list of sender keys is all key_agreements of did doc
        // or filtered to keep only provided key
        let from_kids: Vec<_> = from_ddoc
            .key_agreements
            .iter()
            .filter(|kid| from_kid.map(|from_kid| kid == &from_kid).unwrap_or(true))
            .map(|s| s.as_str())
            .collect();

        if from_kids.is_empty() {
            Err(err_msg(
                ErrorKind::DIDUrlNotFound,
                "No sender key agreements found",
            ))?
        }

        // Keep only sender keys present in the wallet
        let from_kids = secrets_resolver
            .find_secrets(&from_kids)
            .await
            .context("Unable find secrets")?;

        if from_kids.is_empty() {
            Err(err_msg(
                ErrorKind::SecretNotFound,
                "No sender secrets found",
            ))?
        }

        // Resolve materials for sender keys
        let from_keys = from_kids
            .into_iter()
            .map(|kid| {
                from_ddoc
                    .verification_methods
                    .iter()
                    .find(|vm| vm.id == kid)
                    .ok_or_else(|| {
                        // TODO: support external keys
                        err_msg(
                            ErrorKind::Malformed,
                            format!(
                                "No verification material found for sender key agreement {}",
                                kid
                            ),
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;

        // Initial list of recipient keys is all key_agreements of did doc
        // or filtered to keep only provided key
        let to_kids: Vec<_> = to_ddoc
            .key_agreements
            .iter()
            .filter(|kid| to_kid.map(|to_kid| kid == &to_kid).unwrap_or(true))
            .map(|s| s.as_str())
            .collect();

        if to_kids.is_empty() {
            Err(err_msg(
                ErrorKind::DIDUrlNotFound,
                "No recepient key agreements found",
            ))?
        }

        // Resolve materials for keys
        let to_keys = to_kids
            .into_iter()
            .map(|kid| {
                to_ddoc
                    .verification_methods
                    .iter()
                    .find(|vm| vm.id == kid)
                    .ok_or_else(|| {
                        // TODO: support external keys
                        err_msg(
                            ErrorKind::Malformed,
                            format!(
                                "No verification material found for recepient key agreement {}",
                                kid
                            ),
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;

        // Looking for first sender key that has supported crypto and intersection with recipient keys
        let from_key = from_keys
            .iter()
            .filter(|key| key.key_alg() != KnownKeyAlg::Unsupported)
            .find(|from_key| {
                to_keys
                    .iter()
                    .find(|to_key| to_key.key_alg() == from_key.key_alg())
                    .is_some()
            })
            .map(|&key| key)
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::NoCompatibleCrypto,
                    "No common keys between sender and recepient found",
                )
            })?;

        let from_priv_key = secrets_resolver
            .get_secret(&from_key.id)
            .await
            .context("Unable resolve sender secret")?
            .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Sender secret not found"))?;

        let key_alg = from_key.key_alg();

        // Keep only recipient keys compatible with sender key
        let to_keys: Vec<_> = to_keys
            .into_iter()
            .filter(|key| key.key_alg() == key_alg)
            .collect();

        let msg = match key_alg {
            KnownKeyAlg::X25519 => {
                let _to_keys = to_keys
                    .iter()
                    .map(|vm| vm.as_x25519().map(|k| (&vm.id, k)))
                    .collect::<Result<Vec<_>>>()?;

                let to_keys: Vec<_> = _to_keys
                    .iter()
                    .map(|(id, key)| (id.as_str(), key))
                    .collect();

                let msg = match enc_alg_auth {
                    AuthCryptAlg::A256CBC_HS512_ECDH_1PU_A256KW => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        Ecdh1PU<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg,
                        jwe::Algorithm::Ecdh1puA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        Some((&from_key.id, &from_priv_key.as_x25519()?)),
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                };

                if protect_sender {
                    match enc_alg_anon {
                        AnonCryptAlg::A256CBC_HS512_ECDH_ES_A256KW => jwe::encrypt::<
                            AesKey<A256CbcHs512>,
                            EcdhEs<'_, X25519KeyPair>,
                            X25519KeyPair,
                            AesKey<A256Kw>,
                        >(
                            msg.as_bytes(),
                            jwe::Algorithm::EcdhEsA256kw,
                            jwe::EncAlgorithm::A256cbcHs512,
                            None,
                            &to_keys,
                        )
                        .context("Unable produce authcrypt envelope")?,
                        AnonCryptAlg::XC20P_ECDH_ES_A256KW => jwe::encrypt::<
                            Chacha20Key<XC20P>,
                            EcdhEs<'_, X25519KeyPair>,
                            X25519KeyPair,
                            AesKey<A256Kw>,
                        >(
                            msg.as_bytes(),
                            jwe::Algorithm::EcdhEsA256kw,
                            jwe::EncAlgorithm::A256cbcHs512,
                            None,
                            &to_keys,
                        )
                        .context("Unable produce authcrypt envelope")?,
                        AnonCryptAlg::A256GCM_ECDH_ES_A256KW => jwe::encrypt::<
                            AesKey<A256Gcm>,
                            EcdhEs<'_, X25519KeyPair>,
                            X25519KeyPair,
                            AesKey<A256Kw>,
                        >(
                            msg.as_bytes(),
                            jwe::Algorithm::EcdhEsA256kw,
                            jwe::EncAlgorithm::A256cbcHs512,
                            None,
                            &to_keys,
                        )
                        .context("Unable produce authcrypt envelope")?,
                    }
                } else {
                    msg
                }
            }
            KnownKeyAlg::P256 => {
                let _to_keys = to_keys
                    .iter()
                    .map(|vm| vm.as_p256().map(|k| (&vm.id, k)))
                    .collect::<Result<Vec<_>>>()?;

                let to_keys: Vec<_> = _to_keys
                    .iter()
                    .map(|(id, key)| (id.as_str(), key))
                    .collect();

                let msg = match enc_alg_auth {
                    AuthCryptAlg::A256CBC_HS512_ECDH_1PU_A256KW => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        Ecdh1PU<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg,
                        jwe::Algorithm::Ecdh1puA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        Some((&from_key.id, &from_priv_key.as_p256()?)),
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                };

                if protect_sender {
                    match enc_alg_anon {
                        AnonCryptAlg::A256CBC_HS512_ECDH_ES_A256KW => jwe::encrypt::<
                            AesKey<A256CbcHs512>,
                            EcdhEs<'_, P256KeyPair>,
                            P256KeyPair,
                            AesKey<A256Kw>,
                        >(
                            msg.as_bytes(),
                            jwe::Algorithm::EcdhEsA256kw,
                            jwe::EncAlgorithm::A256cbcHs512,
                            None,
                            &to_keys,
                        )
                        .context("Unable produce authcrypt envelope")?,
                        AnonCryptAlg::XC20P_ECDH_ES_A256KW => jwe::encrypt::<
                            Chacha20Key<XC20P>,
                            EcdhEs<'_, P256KeyPair>,
                            P256KeyPair,
                            AesKey<A256Kw>,
                        >(
                            msg.as_bytes(),
                            jwe::Algorithm::EcdhEsA256kw,
                            jwe::EncAlgorithm::A256cbcHs512,
                            None,
                            &to_keys,
                        )
                        .context("Unable produce authcrypt envelope")?,
                        AnonCryptAlg::A256GCM_ECDH_ES_A256KW => jwe::encrypt::<
                            AesKey<A256Gcm>,
                            EcdhEs<'_, P256KeyPair>,
                            P256KeyPair,
                            AesKey<A256Kw>,
                        >(
                            msg.as_bytes(),
                            jwe::Algorithm::EcdhEsA256kw,
                            jwe::EncAlgorithm::A256cbcHs512,
                            None,
                            &to_keys,
                        )
                        .context("Unable produce authcrypt envelope")?,
                    }
                } else {
                    msg
                }
            }
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported recepient key agreement method",
            ))?,
        };

        let to_kids: Vec<_> = to_keys.into_iter().map(|vm| vm.id.clone()).collect();
        Ok((msg, from_key.id.clone(), to_kids))
    }

    async fn _anoncrypt<'dr, 'sr>(
        to: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        msg: &[u8],
        enc_alg_anon: &AnonCryptAlg,
    ) -> Result<(String, Vec<String>)> /* (msg, to_kids) */ {
        let (to_did, to_kid) = did_or_url(to);

        let to_ddoc = did_resolver
            .resolve(to_did)
            .await
            .context("Unable resolve recepient did")?
            .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Recepient did not found"))?;

        // Initial list of recipient key ids is all key_agreements of did doc
        // or one key if url was explicitly provided.
        let to_kids: Vec<_> = to_ddoc
            .key_agreements
            .iter()
            .filter(|kid| to_kid.map(|to_kid| kid == &to_kid).unwrap_or(true))
            .map(|s| s.as_str())
            .collect();

        if to_kids.is_empty() {
            Err(err_msg(
                ErrorKind::DIDUrlNotFound,
                "No recepient key agreements found",
            ))?
        }

        // Resolve materials for keys and determine key types
        // TODO: support external keys
        let to_keys = to_kids
            .into_iter()
            .map(|kid| {
                to_ddoc
                    .verification_methods
                    .iter()
                    .find(|vm| vm.id == kid)
                    .ok_or_else(|| {
                        err_msg(
                            ErrorKind::Unsupported,
                            "External keys are unsupported in this version",
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;

        // Looking for first supported key to determine what key alg use
        let key_alg = to_keys
            .iter()
            .filter(|key| key.key_alg() != KnownKeyAlg::Unsupported)
            .map(|key| key.key_alg())
            .next()
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::InvalidState,
                    "No key agreement keys found for recepient",
                )
            })?;

        // Keep only keys with determined key alg
        let to_keys: Vec<_> = to_keys
            .iter()
            .filter(|key| key.key_alg() == key_alg)
            .collect();

        let msg = match key_alg {
            KnownKeyAlg::X25519 => {
                let _to_keys = to_keys
                    .iter()
                    .map(|vm| vm.as_x25519().map(|k| (&vm.id, k)))
                    .collect::<Result<Vec<_>>>()?;

                let to_keys: Vec<_> = _to_keys
                    .iter()
                    .map(|(id, key)| (id.as_str(), key))
                    .collect();

                match enc_alg_anon {
                    AnonCryptAlg::A256CBC_HS512_ECDH_ES_A256KW => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg,
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce anoncrypt envelope")?,
                    AnonCryptAlg::XC20P_ECDH_ES_A256KW => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg,
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce anoncrypt envelope")?,
                    AnonCryptAlg::A256GCM_ECDH_ES_A256KW => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg,
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce anoncrypt envelope")?,
                }
            }
            KnownKeyAlg::P256 => {
                let _to_keys = to_keys
                    .iter()
                    .map(|vm| vm.as_p256().map(|k| (&vm.id, k)))
                    .collect::<Result<Vec<_>>>()?;

                let to_keys: Vec<_> = _to_keys
                    .iter()
                    .map(|(id, key)| (id.as_str(), key))
                    .collect();

                match enc_alg_anon {
                    AnonCryptAlg::A256CBC_HS512_ECDH_ES_A256KW => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg,
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce anoncrypt envelope")?,
                    AnonCryptAlg::XC20P_ECDH_ES_A256KW => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg,
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce anoncrypt envelope")?,
                    AnonCryptAlg::A256GCM_ECDH_ES_A256KW => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg,
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce anoncrypt envelope")?,
                }
            }
            _ => Err(err_msg(
                ErrorKind::InvalidState,
                "Unsupported recepient key agreement alg",
            ))?,
        };

        let to_kids: Vec<_> = to_keys.into_iter().map(|vm| vm.id.clone()).collect();
        Ok((msg, to_kids))
    }
}

/// Allow fine configuration of packing process.
pub struct PackEncryptedOptions {
    /// If `true` and message is authenticated than information about sender will be protected from mediators, but
    /// additional re-encryption will be required. For anonymous messages this property will be ignored.
    pub protect_sender: bool,

    /// Whether the encrypted messages need to be wrapped into `Forward` messages to be sent to Mediators
    /// as defined by the `Forward` protocol.
    pub forward: bool,

    /// if forward is enabled these optional headers can be passed to the wrapping `Forward` messages.
    /// If forward is disabled this property will be ignored.
    pub forward_headers: Option<Vec<(String, Value)>>,

    /// Identifier (DID URL) of messaging service (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
    /// If DID contains multiple messaging services it allows specify what service to use.
    /// If not present first service will be used.
    pub messaging_service: Option<String>,

    /// Algorithm used for authenticated encryption
    pub enc_alg_auth: AuthCryptAlg,

    /// Algorithm used for anonymous encryption
    pub enc_alg_anon: AnonCryptAlg,
}

impl Default for PackEncryptedOptions {
    fn default() -> Self {
        PackEncryptedOptions {
            protect_sender: false,
            forward: true,
            forward_headers: None,
            messaging_service: None,
            enc_alg_auth: AuthCryptAlg::A256CBC_HS512_ECDH_1PU_A256KW,
            enc_alg_anon: AnonCryptAlg::XC20P_ECDH_ES_A256KW,
        }
    }
}

/// Additional metadata about this `encrypt` method execution like used keys identifiers,
/// used messaging service.
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
pub struct MessagingServiceMetadata {
    /// Identifier (DID URL) of used messaging service.
    pub id: String,

    /// Service endpoint of used messaging service.
    pub service_endpoint: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    use crate::test_vectors::{ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC};
    use crate::{did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver};

    #[tokio::test]
    async fn pack_encrypted_works() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let msg = Message::build(
            "example-1".into(),
            "example/v1".into(),
            json!("example-body"),
        )
        .from(ALICE_DID.into())
        .to(BOB_DID.into())
        .finalize();

        let (_msg, _metadata) = msg
            .pack_encrypted(
                BOB_DID,
                Some(ALICE_DID),
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
    }
}
