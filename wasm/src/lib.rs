mod did_resolver;
mod error;
mod message;
mod secrets_resolver;
mod utils;

pub use crate::{did_resolver::DIDResolver, message::Message, secrets_resolver::SecretsResolver};

use crate::{did_resolver::JsDIDResolver, secrets_resolver::JsSecretsResolver};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
