use std::{collections::HashMap, rc::Rc};

use crate::{did::JsDIDResolver, error::JsResult, DIDResolver};
use crate::{utils::set_panic_hook, Message};
use didcomm::{
    algorithms::AnonCryptAlg,
    error::{ErrorKind, ResultExt},
    protocols::routing::{try_parse_forward, wrap_in_forward},
};
use js_sys::Promise;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen]
pub struct ParsedForward(pub(crate) Rc<didcomm::protocols::routing::ParsedForward<'static>>);

#[wasm_bindgen]
impl ParsedForward {
    #[wasm_bindgen(skip_typescript)]
    pub fn as_value(&self) -> Result<JsValue, JsValue> {
        let msg = JsValue::from_serde(&*self.0)
            .kind(ErrorKind::Malformed, "Unable serialize ParsedForward")
            .as_js()?;

        Ok(msg)
    }
}

#[wasm_bindgen]
impl Message {
    #[wasm_bindgen(skip_typescript)]
    pub fn wrap_in_forward(
        msg: String,
        headers: JsValue,
        to: String,
        routing_keys: JsValue,
        enc_alg_anon: JsValue,
        did_resolver: DIDResolver,
    ) -> Promise {
        // TODO: Better place?
        set_panic_hook();

        let did_resolver = JsDIDResolver(did_resolver);
        future_to_promise(async move {
            let headers: HashMap<String, Value> = headers
                .into_serde()
                .kind(ErrorKind::Malformed, "headers param is malformed")
                .as_js()?;

            let routing_keys: Vec<String> = routing_keys
                .into_serde()
                .kind(ErrorKind::Malformed, "routing_keys param is malformed")
                .as_js()?;

            let enc_alg_anon: AnonCryptAlg = enc_alg_anon
                .into_serde()
                .kind(ErrorKind::Malformed, "enc_alg_anon param is malformed")
                .as_js()?;

            let res = wrap_in_forward(
                &msg,
                Some(&headers),
                &to,
                &routing_keys,
                &enc_alg_anon,
                &did_resolver,
            )
            .await
            .as_js()?;

            Ok(res.into())
        })
    }

    #[wasm_bindgen(skip_typescript)]
    pub fn try_parse_forward(&self) -> Result<JsValue, JsValue> {
        let msg = self.0.clone();
        let parsed_message = try_parse_forward(&msg);
        Ok(JsValue::from_serde(&parsed_message)
            .kind(
                ErrorKind::Malformed,
                "Unable serialize parsed forward message",
            )
            .as_js()?)
    }
}

#[wasm_bindgen(typescript_custom_section)]
const PARSED_FORWARD_AS_VALUE_TS: &'static str = r#"
interface ParsedForward {
    as_value(): IParsedForward;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IParsedForward")]
    pub type IParsedForward;
}

#[wasm_bindgen(typescript_custom_section)]
const IPARSED_FORWARD_TS: &'static str = r#"
type IParsedForward = {
    msg: Message,
    next: string,
    forwarded_msg: any
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const MESSAGE_WRAP_IN_FORWARD_TS: &'static str = r#"
export namespace Message {
    /**
     * Resolves recipient DID DOC Service and Builds Forward envelops if needed.
     * 
     * Wraps the given packed DIDComm message in Forward messages for every routing key.
     * 
     * @param msg the message to be wrapped in Forward messages
     * @param headers optional headers for Forward message
     * @param to recipient's DID (DID URL)
     * @param routing_keys list of routing keys
     * @param enc_alg_anon The encryption algorithm to be used for anonymous encryption (anon_crypt)
     * @param did_resolver instance of `DIDResolver` to resolve DIDs.
     * 
     * @returns a top-level packed Forward message as JSON string
     * 
     * @throws DIDCommDIDNotResolved
     * @throws DIDCommDIDUrlNotFound
     * @throws DIDCommIoError
     * @throws DIDCommInvalidState
     * @throws DIDCommIllegalArgument
     */
    function wrap_in_forward(
        msg: string,
        headers: Record<string, string>,
        to: string,
        routing_keys: Array<string>, 
        enc_alg_anon: string,
        did_resolver: DIDResolver,
    ): Promise<string>;
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const MESSAGE_TRY_PARSE_FORWARD_TS: &'static str = r#"
interface Message {
    /**
     * Tries to parse the Message to a Forward message
     * 
     * @returns a parsed message or null
     */
    try_parse_forward(): ParsedForward;
}
"#;
