use serde::Serialize;
use serde_json::Value;

use crate::Message;

/// Utility structure providing convinient access to Forward plaintext message fields.
#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct ParsedForward<'a> {
    pub msg: &'a Message,
    pub next: String,
    pub forwarded_msg: Value,
}
