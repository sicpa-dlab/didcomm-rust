mod common;
mod did;
mod didcomm;
mod secrets;

use crate::kms::KidOrJwkAdapted;
pub use common::ErrorCode;
pub use common::JsonValue;
pub use did::resolvers::*;
pub use did::*;
pub use didcomm::*;
pub use didcomm_core::{
    algorithms::*,
    did::{
        DIDCommMessagingService, DIDDoc, Service, ServiceKind, VerificationMaterial,
        VerificationMethod, VerificationMethodType,
    },
    error::*,
    secrets::{
        resolvers::example::{Secret, SecretMaterial, SecretType},
        KidOrJwk, KnownKeyAlg, KnownSignatureType,
    },
    *,
};
pub use secrets::resolvers::*;
pub use secrets::*;

#[cfg(test)]
mod test_helper;

uniffi::include_scaffolding!("didcomm");
