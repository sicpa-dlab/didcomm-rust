use didcomm::{
    error::{ErrorKind, ResultExt},
    UnpackOptions,
};
use js_sys::{Array, Promise};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::{
    error::JsResult, DIDResolver, JsDIDResolver, JsSecretsResolver, Message, SecretsResolver,
    utils::set_panic_hook,
};

#[wasm_bindgen]
impl Message {
    pub fn unpack(
        msg: String,
        did_resolver: DIDResolver,
        secrets_resolver: SecretsResolver,
        options: JsValue,
    ) -> Promise {
        // TODO: Better place?
        set_panic_hook();

        let did_resolver = JsDIDResolver(did_resolver);
        let secrets_resolver = JsSecretsResolver(secrets_resolver);

        future_to_promise(async move {
            let options: UnpackOptions = options
                .into_serde()
                .kind(ErrorKind::Malformed, "Options param is malformed")
                .as_js()?;

            let (msg, metadata) =
                didcomm::Message::unpack(&msg, &did_resolver, &secrets_resolver, &options)
                    .await
                    .as_js()?;

            let metadata = JsValue::from_serde(&metadata)
                .kind(ErrorKind::InvalidState, "Unable serialize UnpackMetadata")
                .as_js()?;

            let res = {
                let res = Array::new_with_length(2);
                res.set(0, Message(msg).into());
                res.set(1, metadata);
                res
            };

            Ok(res.into())
        })
    }
}
