use didcomm::{
    error::{ErrorKind, ResultExt},
    PackEncryptedOptions,
};
use js_sys::{Array, Promise};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::{
    error::JsResult, DIDResolver, JsDIDResolver, JsSecretsResolver, Message, SecretsResolver,
};

#[wasm_bindgen]
impl Message {
    #[wasm_bindgen(skip_typescript)]
    pub fn pack_encrypted(
        &self,
        to: String,
        from: Option<String>,
        sign_by: Option<String>,
        did_resolver: DIDResolver,
        secrets_resolver: SecretsResolver,
        options: JsValue,
    ) -> Promise {
        let msg = self.0.clone();
        let did_resolver = JsDIDResolver(did_resolver);
        let secrets_resolver = JsSecretsResolver(secrets_resolver);

        future_to_promise(async move {
            let options: PackEncryptedOptions = options
                .into_serde()
                .kind(ErrorKind::Malformed, "Options param is malformed")
                .as_js()?;

            let (msg, metadata) = msg
                .pack_encrypted(
                    &to,
                    from.as_deref(),
                    sign_by.as_deref(),
                    &did_resolver,
                    &secrets_resolver,
                    &options,
                )
                .await
                .as_js()?;

            let metadata = JsValue::from_serde(&metadata)
                .kind(
                    ErrorKind::InvalidState,
                    "Unable serialize PackEncryptedMetadata",
                )
                .as_js()?;

            let res = {
                let res = Array::new_with_length(2);
                res.set(0, msg.into());
                res.set(1, metadata);
                res
            };

            Ok(res.into())
        })
    }
}

#[wasm_bindgen(typescript_custom_section)]
const MESSAGE_PACK_ENCRYPTED_TS: &'static str = r#"
interface Message {
    /**
     * Produces `DIDComm Encrypted Message`
     * https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-message.
     *
     * A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) and
     * hides its content from all but authorized recipients, discloses (optionally) and proves
     * the sender to exactly and only those recipients, and provides integrity guarantees.
     * It is important in privacy-preserving routing. It is what normally moves over network
     * transports in DIDComm applications, and is the safest format for storing DIDComm data at rest.
     *
     * Encryption is done as following:
     *  - Encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
     *  - if `to` is a DID, then multiplex encryption is done for all keys from the
     *    receiver's `keyAgreement` verification relationship
     *    which are compatible the sender's key.
     *  - if `to` is a key ID, then encryption is done for the receiver's `keyAgreement`
     *    verification method identified by the given key ID.
     *  - if `from` is a DID, then sender `keyAgreement` will be negotiated based on recipient preference and
     *    sender-recipient crypto compatibility.
     *  - if `from` is a key ID, then the sender's `keyAgreement` verification method
     *    identified by the given key ID is used.
     *  - if `from` is None, then anonymous encryption is done and there will be no sender authentication property.
     *
     * It's possible to add non-repudiation by providing `sign_by` parameter.
     *
     * @param `to` recipient DID or key ID the sender uses encryption.
     * @param `from` a sender DID or key ID. If set message will be repudiable authenticated or anonymous otherwise.
     *    Must match `from` header in Plaintext if the header is set.
     * @param `sign_by` if `Some` message will be additionally signed to provide additional non-repudiable authentication
     *    by provided DID/Key. Signed messages are only necessary when the origin of plaintext must be provable
     *    to third parties, or when the sender can’t be proven to the recipient by authenticated encryption because
     *    the recipient is not known in advance (e.g., in a broadcast scenario).
     *    Adding a signature when one is not needed can degrade rather than enhance security because
     *    it relinquishes the sender’s ability to speak off the record.
     * @param `did_resolver` instance of `DIDResolver` to resolve DIDs.
     * @param `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets.
     * @param `options` allow fine configuration of packing process.
     *
     * @returns Tuple `[encrypted_message, metadata]`.
     * - `encrypted_message` A DIDComm encrypted message as a JSON string.
     * - `metadata` additional metadata about this `pack` execution like used keys identifiers,
     *   used messaging service.
     * 
     * @throws DIDCommDIDNotResolved
     * @throws DIDCommDIDUrlNotFound
     * @throws DIDCommMalformed
     * @throws DIDCommIoError
     * @throws DIDCommInvalidState
     * @throws DIDCommNoCompatibleCrypto
     * @throws DIDCommUnsupported
     * @throws DIDCommIllegalArgument
     */
    pack_encrypted(
        to: string, 
        from: string | null,
        sign_by: string | null, 
        did_resolver: DIDResolver,
        secrets_resolver: SecretsResolver,
        options: PackEncryptedOptions,
    ): Promise<[string, PackEncryptedMetadata]>;
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const PACK_ENCRYPTED_OPTIONS_TS: &'static str = r#"
/**
 *  Allow fine configuration of packing process.
 */
type PackEncryptedOptions = {
    /**
     * If `true` and message is authenticated than information about sender will be protected from mediators, but
     * additional re-encryption will be required. For anonymous messages this property will be ignored.
     * Default false.
     */
    protect_sender?: boolean,

    /**
     * Whether the encrypted messages need to be wrapped into `Forward` messages to be sent to Mediators
     * as defined by the `Forward` protocol.
     * Default true.
     */
    forward?: boolean,

    /**
     * if forward is enabled these optional headers can be passed to the wrapping `Forward` messages.
     * If forward is disabled this property will be ignored.
     */
    forward_headers?: Array<[string, string]>,

    /**
     * Identifier (DID URL) of messaging service (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
     * If DID contains multiple messaging services it allows specify what service to use.
     * If not present first service will be used.
     */
    messaging_service?: string,

    /**
     *  Algorithm used for authenticated encryption.
     * Default "A256cbcHs512Ecdh1puA256kw"
     */
    enc_alg_auth?: "A256cbcHs512Ecdh1puA256kw",

    /**
     * Algorithm used for anonymous encryption.
     * Default "Xc20pEcdhEsA256kw"
     */
    enc_alg_anon?: "A256cbcHs512EcdhEsA256kw" | "Xc20pEcdhEsA256kw" | "A256gcmEcdhEsA256kw",
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const PACK_ENCRYPTED_METADATA_TS: &'static str = r#"
/**
 * Additional metadata about this `encrypt` method execution like used keys identifiers,
 * used messaging service.
 */
type PackEncryptedMetadata = {
    /**
     * Information about messaging service used for message preparation.
     * Practically `service_endpoint` field can be used to transport the message.
     */
    messaging_service?: MessagingServiceMetadata,

    /** 
     * Identifier (DID URL) of sender key used for message encryption.
     */
    from_kid?: string,

    /**
     * Identifier (DID URL) of sender key used for message sign.
     */
    sign_by_kid?: string,

    /**
     * Identifiers (DID URLs) of recipient keys used for message encryption.
     */
    to_kids: Array<string>,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const MESSAGING_SERVICE_METADATA_TS: &'static str = r#"
/**
 * Information about messaging service used for message preparation.
 * Practically `service_endpoint` field can be used to transport the message.
 */
type MessagingServiceMetadata = {
    /**
     * Identifier (DID URL) of used messaging service.
     */
    id: string,

    /**
     * Service endpoint of used messaging service.
     */
    service_endpoint: string,
}
"#;
