mod example;

#[cfg(test)]
mod mock;

pub use example::ExampleDIDResolver;

#[cfg(test)]
pub(crate) use mock::MockDidResolver;
