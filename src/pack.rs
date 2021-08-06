use serde_json::Value;

use crate::{did::DIDResolver, error::Result, secrets::SecretsResolver, Message};

impl Message {
    pub async fn pack<DR: DIDResolver, SR: SecretsResolver>(
        &self,
        _from: Option<String>,
        _to: String,
        _did_resolver: &DR,
        _secrets_resolver: &SR,
        _options: Option<String>,
    ) -> Result<String> {
        unimplemented!();
    }
}

pub struct PackOptions {
    /// If true and message is authenticated than information about sender will be hidden from mediators.
    pub hide_sender: bool,

    /// If true and message is authenticated than it will be non-repudiable (additionally signed).
    pub non_repudiation: bool,

    /// Whether the packed messages need to be wrapped into Forward messages to be sent to Mediators
    /// as defined by the Forward protocol.
    pub forward: bool,

    /// if forward is enabled (true by default),
    /// optional headers can be passed to the wrapping Forward messages.
    pub forward_headers: Option<Vec<(String, Value)>>,
}

impl Default for PackOptions {
    fn default() -> Self {
        PackOptions {
            hide_sender: true,
            non_repudiation: false,
            forward: true,
            forward_headers: None,
        }
    }
}
