//! Storage for the validation archive.
//!
//! The archive is written in segments. The current segment is an append-only
//! journal. A closed segment is compressed and gets a seal that includes the
//! hash of the previous seal, so a segment cannot be replaced or dropped from
//! the middle without it showing.
//!
//! We store the original: the raw signed validation exactly as the network
//! sent it, plus the receive time and the ledger index for navigation.
//! Everything else is derived from the original.

pub mod journal;
pub mod record;
pub mod seal;
pub mod segment;

pub use record::Record;
pub use seal::Seal;
pub use segment::{SegmentConfig, SegmentWriter};

/// Storage errors.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// The file is not in our format, or is damaged where damage is not tolerated.
    Format(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o: {e}"),
            Error::Json(e) => write!(f, "json: {e}"),
            Error::Format(e) => write!(f, "format: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
