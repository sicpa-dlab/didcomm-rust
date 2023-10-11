mod did;
mod error;
mod message;
mod secrets;
mod utils;

pub use crate::{
    did::DIDResolver,
    message::{FromPrior, Message},
    secrets::KeyManagementService,
};
use crate::{did::JsDIDResolver, secrets::JsKeyManagementService};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
