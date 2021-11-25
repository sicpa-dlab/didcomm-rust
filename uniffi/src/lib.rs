mod common;
mod did;
mod didcomm;
mod message;
mod secrets;

pub use common::ErrorCode;
pub use common::JsonValue;
pub use did::resolvers::*;
pub use did::*;
pub use didcomm::*;
pub use didcomm_core::algorithms::*;
pub use didcomm_core::did::*;
pub use didcomm_core::error::*;
pub use didcomm_core::secrets::*;
pub use didcomm_core::*;
pub use message::*;
pub use secrets::resolvers::*;
pub use secrets::*;

#[cfg(test)]
mod test_vectors;

uniffi_macros::include_scaffolding!("didcomm");
