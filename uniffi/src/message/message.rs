use std::sync::Arc;

use didcomm::Message;
use serde_json::Value;

pub struct MessageExt(Arc<Message>);

// TODO: finalize
impl MessageExt {
    pub fn new(id: String, type_: String, body: Value) -> Self {
        MessageExt(Arc::new(Message::build(id, type_, body).finalize()))
    }

    pub fn get_id(&self) -> &String {
        &self.0.id
    }
    pub fn get_type(&self) -> &String {
        &self.0.type_
    }
    pub fn get_body(&self) -> &Value {
        &self.0.body
    }
}
