//! Set of intrfaces that describe DID Document secrets

use crate::error::Result;

/// Represents DID Document secrets
pub trait DIDSecrets {
    fn key_agreements(&self) -> Vec<Box<dyn DIDKeyAgreementSecret>>;
    fn key_agreement(&self, kid: &str) -> Box<dyn DIDKeyAgreementSecret>;
    fn authentications(&self) -> Vec<Box<dyn DIDAuthenticationSecret>>;
    fn authentication(&self, kid: &str) -> Box<dyn DIDAuthenticationSecret>;
}

/// Represents secrets for KeyAgreement record
pub trait DIDKeyAgreementSecret {
    /// Returns secrets as JWK
    fn as_jwk(&self) -> Result<String>; // public JWK
}

/// Represents secrets for Authentication record
pub trait DIDAuthenticationSecret {
     /// Returns secrets as JWK
    fn as_jwk(&self) -> Result<String>; // public JWK
}