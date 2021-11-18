mod message;
mod did;
mod secrets;
mod common;

pub use didcomm::*;
pub use didcomm::error::*;
pub use common::ErrorCode;
pub use common::JsonObject;
pub use message::*;
pub use did::*;
pub use secrets::*;


#[cfg(test)]
mod test_vectors;

uniffi_macros::include_scaffolding!("didcomm");