mod did_resolver;
mod message;
mod secrets_resolver;

#[cfg(test)]
pub(crate) use crate as didcomm;

#[cfg(test)]
mod test_vectors;

uniffi_macros::include_scaffolding!("didcomm");
