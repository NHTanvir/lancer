use std::io;

use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("invalid scope rule: {0}")]
    InvalidScope(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("utf8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unsupported feature: {0}")]
    Unsupported(&'static str),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }

    pub fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }
}
