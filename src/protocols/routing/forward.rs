use serde_json::Value;

use crate::Message;

/// Utility structure providing convinient access to Forward plaintext message fields.
pub struct ParsedForward<'a> {
    pub msg: &'a Message,
    pub next: String,
    pub forwarded_msg: Value,
}
