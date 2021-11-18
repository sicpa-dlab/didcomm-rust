mod common;
mod did;
mod message;
mod secrets;

pub use common::ErrorCode;
pub use common::JsonObject;
pub use did::*;
pub use didcomm::algorithms::*;
pub use didcomm::error::*;
pub use didcomm::*;
pub use message::*;
pub use secrets::*;

#[cfg(test)]
mod test_vectors;

uniffi_macros::include_scaffolding!("didcomm");
