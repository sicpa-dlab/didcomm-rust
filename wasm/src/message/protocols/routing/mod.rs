use std::{collections::HashMap, rc::Rc};

use crate::{DIDResolver, did::JsDIDResolver, error::JsResult};
use didcomm::{algorithms::AnonCryptAlg, error::{ErrorKind, ResultExt}, protocols::routing::{try_parse_forward, wrap_in_forward}};
use js_sys::{Promise};
use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use crate::{Message, utils::set_panic_hook};

#[wasm_bindgen]
pub struct ParsedForward(pub(crate) Rc<didcomm::protocols::routing::ParsedForward>);

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
                &did_resolver
            ).await.as_js()?;

            Ok(res.into())
        })
    }

    #[wasm_bindgen(skip_typescript)]
    pub fn try_parse_forward(
        msg: JsValue
     ) -> Result<JsValue, JsValue> {
        let msg: didcomm::Message = msg
            .into_serde()
            .kind(ErrorKind::Malformed, "msg param is malformed")
            .as_js()?;

        let parsed_message = try_parse_forward(&msg);
        Ok(
            JsValue::from_serde(&parsed_message)
            .kind(ErrorKind::Malformed, "Unable serialize parsed forward message")
            .as_js()?
        )
    }

}

#[wasm_bindgen(typescript_custom_section)]
const MESSAGE_WRAP_IN_FORWARD_TS: &'static str = r#"
export namespace Message {
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
export namespace Message {
    function try_parse_forward(
        msg: Message
    ): ParsedForward;
}
"#;