//! A publisher's signed UNL.
//!
//! The publisher serves its manifest, the list (`blob`, base64 JSON) and the
//! list signature. The check follows xrpld (`ValidatorList::verify`):
//! 1. the publisher manifest is signed and not revoked;
//! 2. the master key in the manifest is the one we trust as the publisher;
//! 3. the list bytes are signed by the current signing key from that manifest.
//!
//! What is inside the list (validators, sequence, validity dates) is for the
//! caller to parse: the core checks that the bytes are authentic, not what they mean.

use std::fmt;

use crate::keys::{VerifyError, verify};
use crate::manifest::Manifest;
use crate::stobject::Error as CodecError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    Manifest(CodecError),
    ManifestSignature(VerifyError),
    /// The manifest is signed by a master key other than the one we trust.
    WrongPublisher,
    Revoked,
    ListSignature(VerifyError),
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListError::Manifest(e) => write!(f, "cannot parse publisher manifest: {e}"),
            ListError::ManifestSignature(e) => write!(f, "publisher manifest: {e}"),
            ListError::WrongPublisher => f.write_str("manifest of a different publisher"),
            ListError::Revoked => f.write_str("publisher key revoked"),
            ListError::ListSignature(e) => write!(f, "list signature: {e}"),
        }
    }
}

impl std::error::Error for ListError {}

/// Checks the list and returns the verified publisher manifest.
pub fn verify_list(
    publisher_master: &[u8],
    manifest: &[u8],
    blob: &[u8],
    signature: &[u8],
) -> Result<Manifest, ListError> {
    let m = Manifest::parse(manifest).map_err(ListError::Manifest)?;
    m.verify().map_err(ListError::ManifestSignature)?;
    if m.master_key != publisher_master {
        return Err(ListError::WrongPublisher);
    }
    if m.is_revoked() {
        return Err(ListError::Revoked);
    }
    let key = m
        .signing_key
        .as_deref()
        .ok_or(ListError::ManifestSignature(VerifyError::BadKey))?;
    verify(key, blob, signature, true).map_err(ListError::ListSignature)?;
    Ok(m)
}
