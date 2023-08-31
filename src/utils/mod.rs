use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub(crate) mod crypto;
pub(crate) mod did;
pub(crate) mod serde;

pub struct DummyFuture<OUT> {
    value: OUT,
}

impl<OUT> Future for DummyFuture<OUT> {
    type Output = OUT;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
