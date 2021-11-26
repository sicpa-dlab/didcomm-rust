use std::fmt;

use serde::Serialize;
use serde_json::error::Category;

#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub enum ErrorKind {
    #[error("DID not resolved")]
    DIDNotResolved,

    #[error("DID URL not found")]
    DIDUrlNotFound,

    #[error("Secret not found")]
    SecretNotFound,

    #[error("Malformed")]
    Malformed,

    #[error("IO error")]
    IoError,

    #[error("Invalid state")]
    InvalidState,

    #[error("No compatible crypto")]
    NoCompatibleCrypto,

    #[error("Unsupported crypto or method")]
    Unsupported,

    #[error("Illegal argument")]
    IllegalArgument,
}

#[derive(Debug, thiserror::Error)]
#[error("{kind}: {source:#}")]
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

pub trait ResultExtNoContext<T, E> {
    fn to_error_kind(self, kind: ErrorKind) -> std::result::Result<T, ErrorKind>;

    fn kind_no_context<D>(self, kind: ErrorKind, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static;
}

impl<T, E> ResultExtNoContext<T, E> for std::result::Result<T, E> {
    fn to_error_kind(self, kind: ErrorKind) -> std::result::Result<T, ErrorKind> {
        self.map_err(|_| kind)
    }

    fn kind_no_context<D>(self, kind: ErrorKind, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        self.map_err(|_| Error::msg(kind, msg))
    }
}

pub trait ResultContext<T> {
    fn context<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static;
}

impl<T> ResultContext<T> for Result<T> {
    fn context<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        self.map_err(|e| {
            let Error { kind, source } = e;

            Error {
                kind,
                source: source.context(msg),
            }
        })
    }
}

pub trait ToResult<T> {
    fn to_didcomm<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static;
}

impl<T> ToResult<T> for serde_json::Result<T> {
    fn to_didcomm<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        ResultContext::context(self.map_err(|e| e.into()), msg)
    }
}

impl<T> ToResult<T> for bs58::decode::Result<T> {
    fn to_didcomm<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        ResultContext::context(self.map_err(|e| e.into()), msg)
    }
}

impl<T> ToResult<T> for bs58::encode::Result<T> {
    fn to_didcomm<D>(self, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        ResultContext::context(self.map_err(|e| e.into()), msg)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        match err.classify() {
            Category::Io | Category::Eof => Error::msg(ErrorKind::InvalidState, err.to_string()),
            _ => Error::msg(ErrorKind::Malformed, err.to_string()),
        }
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(err: bs58::decode::Error) -> Self {
        match err {
            bs58::decode::Error::BufferTooSmall => {
                Error::msg(ErrorKind::InvalidState, err.to_string())
            }
            _ => Error::msg(ErrorKind::Malformed, err.to_string()),
        }
    }
}

impl From<bs58::encode::Error> for Error {
    fn from(err: bs58::encode::Error) -> Self {
        match err {
            _ => Error::msg(ErrorKind::InvalidState, err.to_string()),
        }
    }
}

pub fn err_msg<D>(kind: ErrorKind, msg: D) -> Error
where
    D: fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    Error::msg(kind, msg)
}
