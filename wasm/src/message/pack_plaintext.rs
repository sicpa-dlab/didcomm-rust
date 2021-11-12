use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::{did_resolver::JsDIDResolver, error::JsResult, DIDResolver, Message};

#[wasm_bindgen]
impl Message {
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
