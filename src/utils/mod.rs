use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub(crate) mod crypto;
pub(crate) mod did;
pub(crate) mod serde;

/// Sized feature needed just for compiler to deduce Sized type
/// Do NOT use as a real feature.
pub struct DummyFuture<OUT> {
    #[allow(dead_code)]
    value: OUT,
}

impl<OUT> Future for DummyFuture<OUT> {
    type Output = OUT;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
