use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::{error::JsResult, DIDResolver, JsDIDResolver, Message};

#[wasm_bindgen(skip_typescript)]
impl Message {
    #[wasm_bindgen(skip_typescript)]
    pub fn pack_plaintext(&self, did_resolver: DIDResolver) -> Promise {
        // TODO: FIXME: think on avoid cloning
        let msg = self.0.clone();
        let did_resolver = JsDIDResolver(did_resolver);

        future_to_promise(async move {
            let msg = msg.pack_plaintext(&did_resolver).await.as_js()?;

            Ok(msg.into())
        })
    }
}

#[wasm_bindgen(typescript_custom_section)]
const MESSAGE_PACK_PLAYNTEXT_TS: &'static str = r#"
interface Message {
    /**
     * Produces `DIDComm Plaintext Messages`
     * https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages.
     * 
     * A DIDComm message in its plaintext form, not packaged into any protective envelope,
     * is known as a DIDComm plaintext message. Plaintext messages lack confidentiality and integrity
     * guarantees, and are repudiable. They are therefore not normally transported across security boundaries.
     * However, this may be a helpful format to inspect in debuggers, since it exposes underlying semantics,
     * and it is the format used in this spec to give examples of headers and other internals.
     * Depending on ambient security, plaintext may or may not be an appropriate format for DIDComm data at rest.
     * 
     * @param `did_resolver` instance of `DIDResolver` to resolve DIDs.
     * 
     * @returns a DIDComm plaintext message s JSON string
     * 
     * @throws DIDCommError
     */
    pack_plaintext(did_resolver: DIDResolver): Promise<string>;
}
"#;
