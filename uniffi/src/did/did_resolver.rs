use std::sync::Arc;

use didcomm_core::did::DIDDoc;

use crate::{common::OnResult, ErrorCode};

/// Represents DID Doc resolver (https://www.w3.org/TR/did-core/#did-resolution).
pub trait FFIDIDResolver: Sync + Send {
    /// Resolves a DID document by the given DID.
    ///
    /// # Params
    /// - `did` a DID to be resolved.
    /// - `cb` a callback with a result
    ///  
    /// # Returns
    /// A result code
    ///
    fn resolve(&self, did: String, cb: Arc<OnDIDResolverResult>) -> ErrorCode;
}

pub type OnDIDResolverResult = OnResult<Option<DIDDoc>>;
