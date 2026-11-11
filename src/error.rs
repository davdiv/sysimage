//! Crate-wide error type.

use std::io;
use thiserror::Error;

/// A specialized [`Result`] for sysimage operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by sysimage.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Build an ad-hoc error from any message.
    pub fn msg<T: Into<String>>(msg: T) -> Self {
        Error::Other(msg.into())
    }
}

/// Shorthand to build an [`Error::Other`] from a format string.
#[macro_export]
macro_rules! bail_msg {
    ($($t:tt)*) => { return Err($crate::error::Error::msg(format!($($t)*))) };
}
