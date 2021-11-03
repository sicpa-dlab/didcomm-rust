use didcomm::error::{ErrorKind, ResultExt};
use wasm_bindgen::prelude::*;

use crate::error::JsResult;

#[wasm_bindgen]
pub struct Message(pub(crate) didcomm::Message);

#[wasm_bindgen]
impl Message {
    #[wasm_bindgen(constructor)]
    pub fn new(value: IMessage) -> Result<Message, JsValue> {
        let msg = value
            .into_serde()
            .kind(ErrorKind::Malformed, "Unable deserialize Message")
            .as_js()?;

        Ok(Message(msg))
    }

    pub fn as_value(&self) -> Result<JsValue, JsValue> {
        let msg = JsValue::from_serde(&self.0)
            .kind(ErrorKind::Malformed, "Unable serialize Message")
            .as_js()?;

        Ok(msg)
    }
}

#[wasm_bindgen(typescript_custom_section)]
const IMESSAGE: &'static str = r#"
type IMessage = {
    "id": string,
    "typ": string,
    "type": string,
    "from": string,
    "to": [string],
    "created_time": number,
    "expires_time": number,
    "body": object,
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IMessage")]
    pub type IMessage;
}
