use crate::error::Result;
use crate::secrets::did_secrets::DIDSecrets;

/**
 * Interface for DID Document secrets resolving.
 */
pub trait DIDSecretsResolver {
    fn resolve(did: &str) -> Result<Box<dyn DIDSecrets>>;
}
