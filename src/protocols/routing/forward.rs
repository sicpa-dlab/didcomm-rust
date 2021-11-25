use serde_json::Value;

use crate::Message;

pub struct ParsedForward<'a> {
    pub msg: &'a Message,
    pub next: String,
    pub forwarded_msg: Value,
}
