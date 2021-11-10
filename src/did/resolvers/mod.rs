mod example;
#[cfg(test)]
pub(crate) mod mock;

pub use example::ExampleDIDResolver;
#[cfg(test)]
pub use mock::MockDidResolver;
