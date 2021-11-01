mod did_resolver;
mod secrets_resolver;
mod utils;

use didcomm::PackSignedMetadata;
use js_sys::Promise;
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

pub use crate::{
    did_resolver::DIDResolver, secrets_resolver::SecretsResolver, utils::set_panic_hook,
};

use crate::{did_resolver::JsDIDResolver, secrets_resolver::JsSecretsResolver};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct Message(didcomm::Message);

#[wasm_bindgen]
impl Message {
    #[wasm_bindgen(constructor)]
    pub fn new(value: JsValue) -> Self {
        // TODO: FIXME: Error handling
        Message(value.into_serde().unwrap())
    }

    pub fn as_value(&self) -> JsValue {
        // TODO: FIXME: Error handling
        JsValue::from_serde(&self.0).unwrap()
    }

    pub fn pack_plaintext(&self) -> Result<String, JsValue> {
        self.0.pack_plaintext().map_err(|e| format!("{}", e).into())
    }

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
                .map_err(|e| JsValue::from(format!("{}", e)))?;

            let res = PackSignedResult { msg, metadata };
            let res = JsValue::from_serde(&res).map_err(|e| format!("{}", e))?;
            Ok(res)
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct PackSignedResult {
    pub msg: String,
    pub metadata: PackSignedMetadata,
}
