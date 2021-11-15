mod pack_encrypted;
mod pack_plaintext;
mod pack_signed;
mod unpack;

use didcomm::error::{ErrorKind, ResultExt};
use wasm_bindgen::prelude::*;

use crate::{error::JsResult, utils::set_panic_hook};

#[wasm_bindgen]
pub struct Message(pub(crate) didcomm::Message);

#[wasm_bindgen]
impl Message {
    #[wasm_bindgen(constructor)]
    pub fn new(value: IMessage) -> Result<Message, JsValue> {
        // TODO: Better place?
        set_panic_hook();

        let msg = value
            .into_serde()
            .kind(ErrorKind::Malformed, "Unable deserialize Message")
            .as_js()?;

        Ok(Message(msg))
    }

    #[wasm_bindgen(skip_typescript)]
    pub fn as_value(&self) -> Result<JsValue, JsValue> {
        let msg = JsValue::from_serde(&self.0)
            .kind(ErrorKind::Malformed, "Unable serialize Message")
            .as_js()?;

        Ok(msg)
    }
}

#[wasm_bindgen(typescript_custom_section)]
const MESSAGE_AS_VALUE_TS: &'static str = r#"
interface Message {
    /**
     * @returns message representation as plain object
     */
    as_value(): IMessage;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IMessage")]
    pub type IMessage;
}

// TODO: FIXME: Provide full typing
#[wasm_bindgen(typescript_custom_section)]
const IMESSAGE_TS: &'static str = r#"
type IMessage = {
    "id": string,
    "typ": string,
    "type": string,
    "from": string,
    "to": [string],
    "created_time": number,
    "expires_time": number,
    "body": object,
} & any;
"#;
