use didcomm::error::{ErrorKind, ResultExt};
use js_sys::{Array, Promise};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::{
    error::JsResult, DIDResolver, JsDIDResolver, JsSecretsResolver, Message, SecretsResolver,
};

#[wasm_bindgen]
impl Message {
    pub fn pack_signed(
        &self,
        sign_by: String,
        did_resolver: DIDResolver,
        secrets_resolver: SecretsResolver,
    ) -> Promise {
        // TODO: FIXME: think on avoid cloning
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
