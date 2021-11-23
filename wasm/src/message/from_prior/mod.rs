mod pack;
mod unpack;

use didcomm::error::{ErrorKind, ResultExt};
use std::rc::Rc;
use wasm_bindgen::prelude::*;

use crate::{error::JsResult, utils::set_panic_hook};

#[wasm_bindgen]
/// Allows building of `from_prior` message header according
/// to DIDComm DID Rotation procedure
/// https://identity.foundation/didcomm-messaging/spec/#did-rotation.
pub struct FromPrior(pub(crate) Rc<didcomm::FromPrior>);

#[wasm_bindgen]
impl FromPrior {
    #[wasm_bindgen(constructor)]
    /// Instantiates FromPrior from plain object
    pub fn new(value: IFromPrior) -> Result<FromPrior, JsValue> {
        // TODO: Better place?
        set_panic_hook();

        let msg = value
            .into_serde()
            .kind(ErrorKind::Malformed, "Unable deserialize FromPrior")
            .as_js()?;

        Ok(FromPrior(Rc::new(msg)))
    }

    #[wasm_bindgen(skip_typescript)]
    pub fn as_value(&self) -> Result<JsValue, JsValue> {
        let msg = JsValue::from_serde(&*self.0)
            .kind(ErrorKind::Malformed, "Unable serialize FromPrior")
            .as_js()?;

        Ok(msg)
    }
}

#[wasm_bindgen(typescript_custom_section)]
const MESSAGE_AS_VALUE_TS: &'static str = r#"
interface FromPrior {
    /**
     * @returns FromPrior representation as plain object
     */
    as_value(): IFromPrior;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IFromPrior")]
    pub type IFromPrior;
}

#[wasm_bindgen(typescript_custom_section)]
const IMESSAGE_TS: &'static str = r#"
type IFromPrior = {
    /**
     * new DID after rotation
     */
    iss: string,

    /**
     * prior DID
     */
    sub: string,

    /**
     * Datetime of the DID rotation
     */
    iat?: number,
}
"#;
