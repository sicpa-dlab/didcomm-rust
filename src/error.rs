use std::fmt;

use serde::Serialize;
use serde_json::error::Category;

#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub enum ErrorKind {
    #[error("DID not resolved")]
    DIDNotResolved,

    #[error("DID not resolved")]
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

pub trait ResultInvalidStateWrapper<T> {
    fn ok_or_invalid_state(self) -> Result<Option<T>>;
    fn wrap_err_or_invalid_state<D>(self, kind: ErrorKind, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static;
}

impl<T> ResultInvalidStateWrapper<T> for Result<T> {
    fn ok_or_invalid_state(self) -> Result<Option<T>> {
        match self {
            Ok(msg) => Ok(Some(msg)),
            Err(err) => match err.kind() {
                ErrorKind::InvalidState => Err(err),
                _ => Ok(None),
            },
        }
    }

    fn wrap_err_or_invalid_state<D>(self, kind: ErrorKind, msg: D) -> Result<T>
    where
        D: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        self.map_err(|e| match e.kind {
            ErrorKind::InvalidState => e,
            _ => err_msg(kind, msg),
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

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        match err.classify() {
            Category::Io | Category::Eof => Error::msg(ErrorKind::InvalidState, err.to_string()),
            _ => Error::msg(ErrorKind::Malformed, err.to_string()),
        }
    }
}

pub fn err_msg<D>(kind: ErrorKind, msg: D) -> Error
where
    D: fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    Error::msg(kind, msg)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ok_or_invalid_state_works() {
        let res = Ok(5).ok_or_invalid_state().expect("expect ok");
        assert_eq!(Some(5), res);

        let res: Option<i32> = Err(err_msg(ErrorKind::Malformed, "malformed"))
            .ok_or_invalid_state()
            .expect("expect ok");
        assert_eq!(None, res);

        let res: Error = Err::<i32, Error>(err_msg(ErrorKind::InvalidState, "invalid state error"))
            .ok_or_invalid_state()
            .expect_err("expect error");
        assert_eq!(ErrorKind::InvalidState, res.kind);
        assert_eq!("Invalid state: invalid state error", format!("{}", res));
    }

    #[test]
    fn wrap_err_or_invalid_state_works() {
        let res = Ok(5)
            .wrap_err_or_invalid_state(ErrorKind::Malformed, "malformed")
            .expect("expect ok");
        assert_eq!(5, res);

        let res: Error = Err::<i32, Error>(err_msg(ErrorKind::Malformed, "malformed"))
            .wrap_err_or_invalid_state(ErrorKind::Unsupported, "unsupported error")
            .expect_err("expect error");
        assert_eq!(ErrorKind::Unsupported, res.kind);
        assert_eq!(
            "Unsupported crypto or method: unsupported error",
            format!("{}", res)
        );

        let res: Error = Err::<i32, Error>(err_msg(ErrorKind::InvalidState, "invalid state error"))
            .wrap_err_or_invalid_state(ErrorKind::Unsupported, "unsupported error")
            .expect_err("expect error");
        assert_eq!(ErrorKind::InvalidState, res.kind);
        assert_eq!("Invalid state: invalid state error", format!("{}", res));
    }
}
