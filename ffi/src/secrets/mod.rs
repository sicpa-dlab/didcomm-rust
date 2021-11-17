pub mod resolvers;

pub(crate) mod secrets_resolver;
pub(crate) mod secrets_resolver_adapter;

pub use secrets_resolver::{FFISecretsResolver};