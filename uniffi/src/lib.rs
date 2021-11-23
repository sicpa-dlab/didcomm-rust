mod common;
mod did;
mod message;
mod secrets;

pub use common::ErrorCode;
pub use common::JsonValue;
pub use did::resolvers::*;
pub use did::*;
pub use didcomm::algorithms::*;
pub use didcomm::did::*;
pub use didcomm::error::*;
pub use didcomm::secrets::*;
pub use didcomm::*;
pub use message::*;
pub use secrets::resolvers::*;
pub use secrets::*;

#[cfg(test)]
mod test_vectors;

uniffi_macros::include_scaffolding!("didcomm");
