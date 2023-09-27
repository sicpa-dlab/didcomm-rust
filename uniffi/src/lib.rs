mod common;
mod did;
mod didcomm;
mod secrets;

pub use common::ErrorCode;
pub use common::JsonValue;
pub use did::resolvers::*;
pub use did::*;
pub use didcomm::*;
pub use didcomm_core::algorithms::*;
pub use didcomm_core::did::{
    DIDCommMessagingService, DIDDoc, Service, ServiceKind, VerificationMaterial,
    VerificationMethod, VerificationMethodType,
};
pub use didcomm_core::error::*;
pub use didcomm_core::secrets::{Secret, SecretMaterial, SecretType};
pub use didcomm_core::*;
pub use secrets::resolvers::*;
pub use secrets::*;

#[cfg(test)]
mod test_helper;

uniffi::include_scaffolding!("didcomm");
