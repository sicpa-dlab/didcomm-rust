pub mod resolvers;

pub(crate) mod did_resolver;
pub(crate) mod did_resolver_adapter;

pub use did_resolver::FFIDIDResolver;
pub use did_resolver_adapter::OnDIDResolverResult;
