//! The witness core: everything needed to check XRPL data yourself,
//! without trusting either a node or a third-party service.
//!
//! Transactions are not executed here. The core only reads and checks what
//! the network has already computed and signed, so it cannot diverge from
//! the reference implementation on edge cases of execution.
//!
//! What the core contains:
//! - `hash`: SHA-512Half and XRPL hash prefixes;
//! - `stobject`: splitting serialized objects into fields, as slices of the original bytes;
//! - `keys`: secp256k1 and ed25519 signatures, `n9…` keys;
//! - `validation`: parsing a validation and checking its signature;
//! - `manifest`: the link between a validator's master key and its signing key;
//! - `unl`: checking a publisher's signed UNL;
//! - `negative_unl`: who the network has temporarily disabled;
//! - `ledger`: the ledger header and its hash;
//! - `shamap`: the transaction tree and inclusion proofs;
//! - `skiplist`: the ledger hash lists in state that link old ledgers to new ones;
//! - `txproof`: a transaction inclusion proof as a portable object;
//! - `quorum`: whether a ledger is confirmed under a given trust policy;
//! - `evidence`: an evidence bundle for one ledger, and checking it.
//!
//! Checking a signature, checking a quorum and checking data are different
//! claims. The core answers the first; the second is built on top, with an
//! explicit trust policy.

pub mod evidence;
pub mod hash;
pub mod keys;
pub mod ledger;
pub mod manifest;
pub mod negative_unl;
pub mod quorum;
pub mod shamap;
pub mod skiplist;
pub mod stateproof;
pub mod stobject;
pub mod txproof;
pub mod unl;
pub mod unlstore;
pub mod util;
pub mod validation;

pub use hash::{HashPrefix, sha512_half, sha512_half_prefixed};
pub use manifest::Manifest;
pub use validation::Validation;
