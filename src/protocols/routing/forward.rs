use serde_json::{Map, Value};

use crate::Message;

pub(crate) struct ParsedForward {
    #[allow(dead_code)]
    pub msg: Message,
    pub next: String,
    pub forwarded_msg: Map<String, Value>,
}
