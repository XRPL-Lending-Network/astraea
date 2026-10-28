//! A manifest is a record signed by the master key saying "my current signing
//! key is such-and-such, record number N".
//!
//! A validator's master key is kept offline; validations are signed by a
//! signing key that can be rotated. The manifest links the two and is
//! signed twice: by the master key (`MasterSignature`) and by the signing key
//! itself (`Signature`), which proves that someone actually holds it. Both
//! signatures cover the `MAN\0` prefix and every field except the signatures.
//!
//! Sequence `0xFFFFFFFF` is a revocation: the master key gives up all signing
//! keys, and such a manifest has neither a signing key nor a second signature.

use crate::HashPrefix;
use crate::keys::{VerifyError, verify};
use crate::stobject::{self, Error, fields as f};

pub const REVOKED: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub sequence: u32,
    pub master_key: Vec<u8>,
    pub signing_key: Option<Vec<u8>>,
    pub domain: Option<String>,
    pub signature: Option<Vec<u8>>,
    pub master_signature: Vec<u8>,
    signing_data: Vec<u8>,
}

impl Manifest {
    pub fn parse(raw: &[u8]) -> Result<Manifest, Error> {
        let fs = stobject::fields(raw)?;
        let sequence = stobject::find(&fs, f::SEQUENCE)
            .and_then(stobject::u32_of)
            .ok_or_else(|| Error::Malformed("missing Sequence".into()))?;
        let master_key = stobject::find(&fs, f::PUBLIC_KEY)
            .ok_or_else(|| Error::Malformed("missing PublicKey".into()))?
            .to_vec();
        let master_signature = stobject::find(&fs, f::MASTER_SIGNATURE)
            .ok_or_else(|| Error::Malformed("missing MasterSignature".into()))?
            .to_vec();
        let mut signing_data = HashPrefix::Manifest.to_bytes().to_vec();
        signing_data.extend(stobject::signing_bytes(&fs));
        Ok(Manifest {
            sequence,
            master_key,
            signing_key: stobject::find(&fs, f::SIGNING_PUB_KEY).map(<[u8]>::to_vec),
            domain: stobject::find(&fs, f::DOMAIN).map(|d| String::from_utf8_lossy(d).into_owned()),
            signature: stobject::find(&fs, f::SIGNATURE).map(<[u8]>::to_vec),
            master_signature,
            signing_data,
        })
    }

    pub fn is_revoked(&self) -> bool {
        self.sequence == REVOKED
    }

    /// Both signatures are present and valid. For a revocation, only the
    /// master key signature, and it must not carry a signing key.
    pub fn verify(&self) -> Result<(), VerifyError> {
        verify(
            &self.master_key,
            &self.signing_data,
            &self.master_signature,
            true,
        )?;
        if self.is_revoked() {
            return match self.signing_key {
                None => Ok(()),
                Some(_) => Err(VerifyError::Mismatch),
            };
        }
        let key = self.signing_key.as_deref().ok_or(VerifyError::BadKey)?;
        let sig = self
            .signature
            .as_deref()
            .ok_or(VerifyError::BadSignatureEncoding)?;
        verify(key, &self.signing_data, sig, true)
    }
}
