use serde::Serialize;
use std::fmt;

#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub enum ErrorKind {
    #[error("DID not resolved.")]
    DIDNotResolved,

    #[error("DID not resolved.")]
    DIDUrlNotFound,

    #[error("Secret not found.")]
    SecretNotFound,

    #[error("Message malformed.")]
    MessageMalformed,

    #[error("Message doesn't meet trust requrements.")]
    MessageUntrusted,

    #[error("IO error.")]
    IoError,

    #[error("Invalid state.")]
    InvalidState,

    #[error("No compatible crypto.")]
    NoCompatibleCrypto,
}

#[derive(Debug, thiserror::Error)]
#[error("{kind}")]
pub struct Error {
    kind: ErrorKind,
    pub source: anyhow::Error,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn new<E>(kind: ErrorKind, source: E) -> Error
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error {
            kind,
            source: anyhow::Error::new(source),
        }
    }

    pub fn msg<D>(kind: ErrorKind, msg: D) -> Error
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        Error {
            kind,
            source: anyhow::Error::msg(msg),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait ResultExt<T, E> {
    fn kind<D>(self, kind: ErrorKind, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static;
}

impl<T, E> ResultExt<T, E> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn kind<D>(self, kind: ErrorKind, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        self.map_err(|e| Error {
            kind,
            source: anyhow::Error::new(e).context(msg),
        })
    }
}

pub type Context<T, E> = dyn anyhow::Context<T, E>;

pub fn err_msg<D>(kind: ErrorKind, msg: D) -> Error
where
    D: fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    Error::msg(kind, msg)
}
