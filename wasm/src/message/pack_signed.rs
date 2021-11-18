use didcomm::error::{ErrorKind, ResultExt};
use js_sys::{Array, Promise};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::{
    error::JsResult, DIDResolver, JsDIDResolver, JsSecretsResolver, Message, SecretsResolver,
};

#[wasm_bindgen(skip_typescript)]
impl Message {
    #[wasm_bindgen(skip_typescript)]
    pub fn pack_signed(
        &self,
        sign_by: String,
        did_resolver: DIDResolver,
        secrets_resolver: SecretsResolver,
    ) -> Promise {
        let msg = self.0.clone();
        let did_resolver = JsDIDResolver(did_resolver);
        let secrets_resolver = JsSecretsResolver(secrets_resolver);

        future_to_promise(async move {
            let (msg, metadata) = msg
                .pack_signed(&sign_by, &did_resolver, &secrets_resolver)
                .await
                .as_js()?;

            let metadata = JsValue::from_serde(&metadata)
                .kind(
                    ErrorKind::InvalidState,
                    "Unable serialize PackSignedMetadata",
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
     * Produces `DIDComm Signed Message`
     * https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-message.
     *
     * Signed messages are not necessary to provide message integrity (tamper evidence),
     * or to prove the sender to the recipient. Both of these guarantees automatically occur
     * with the authenticated encryption in DIDComm encrypted messages. Signed messages are only
     * necessary when the origin of plaintext must be provable to third parties,
     * or when the sender can’t be proven to the recipient by authenticated encryption because
     * the recipient is not known in advance (e.g., in a broadcast scenario).
     * We therefore expect signed messages to be used in a few cases, but not as a matter of course.
     *
     * @param `sign_by` a DID or key ID the sender uses for signing
     * @param `did_resolver` instance of `DIDResolver` to resolve DIDs.
     * @param `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
     *
     * @returns Tuple (signed_message, metadata)
     * - `signed_message` a DIDComm signed message as JSON string
     * - `metadata` additional metadata about this `encrypt` execution like used keys identifiers and algorithms.
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
    pack_signed(
        sign_by: string,
        did_resolver: DIDResolver,
        secrets_resolver: SecretsResolver,
    ): Promise<[string, PackSignedMetadata]>;
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const PACK_SIGNED_METADATA_TS: &'static str = r#"
/**
 * Additional metadata about this `pack` method execution like used key identifiers.
 */
type PackSignedMetadata = {
    /**
     * Identifier (DID URL) of sign key.
     */
    sign_by_kid: String,
}
"#;
