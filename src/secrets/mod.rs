pub(crate) mod did_secrets;
pub(crate) mod did_secrets_resolver;

pub use did_secrets::{DIDAuthenticationSecret, DIDKeyAgreementSecret, DIDSecrets};
pub use did_secrets_resolver::DIDSecretsResolver;
