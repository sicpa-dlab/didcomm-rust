use serde_json::Value;

use crate::Message;

pub struct ParsedForward {
    #[allow(dead_code)]
    pub msg: Message,
    pub next: String,
    pub forwarded_msg: Value,
}
