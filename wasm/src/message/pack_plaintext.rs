use wasm_bindgen::prelude::*;

use crate::{error::JsResult, Message};

#[wasm_bindgen]
impl Message {
    pub fn pack_plaintext(&self) -> Result<String, JsValue> {
        let msg = self.0.pack_plaintext().as_js()?;
        Ok(msg)
    }
}
