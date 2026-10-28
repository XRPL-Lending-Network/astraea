//! Astraea Ledger Engine.
//!
//! Loads validated ledgers from xrpld, checks them before writing and
//! stores the header, transactions with metadata, and state changes.
//!
//! - `api`: Clio-compatible API (ledger, tx, account_tx and others);
//! - `proof`: Proof API, evidence bundles for a ledger, transaction or object;
//! - `server`: HTTP JSON-RPC and WebSocket for `api`;
//! - `source`: xrpld gRPC client (same as Clio: `GetLedger` with objects);
//! - `ledger`: a whole ledger, its verification and serialization for the log;
//! - `blocks`: block storage with random access by ledger;
//! - `confirm`: confirmation of ledgers by a quorum of UNL validators;
//! - `delta`: state changes, diffed against the previous version and metadata;
//! - `history`: history, format 2: transactions as one frame per ledger with a
//!   dictionary, state changes in separate blocks;
//! - `index`: transaction by hash, ledger by hash, account history;
//! - `statetree`: the state tree and its root at every ledger;
//! - `state`: state over time, a snapshot plus object versions (fjall);
//! - `metrics`: loader metrics for Prometheus;
//! - `xrpl_json`: XRPL binary objects as JSON, like `getJson` in xrpld;
//! - `log`: a segmented ledger log. This is the first storage version; a
//!   format with indexes and random access belongs to the storage format work.
//!
//! The node is not trusted blindly: the transaction tree must match the root in
//! the header, otherwise the ledger is not written. Whether the header itself
//! was validated by the network is up to the Proof Engine (witness-core: quorum of validations).

pub mod api;
pub mod blocks;
pub mod cold;
pub mod coldindex;
pub mod confirm;
pub mod delta;
pub mod forward;
pub mod history;
pub mod index;
pub mod ledger;
pub mod log;
pub mod metrics;
pub mod owned;
pub mod proof;
pub mod server;
pub mod source;
pub mod state;
pub mod statetree;
pub mod subs;
pub mod ter;
pub mod txcodec;
pub mod txindex;
pub mod xrpl_json;
pub mod xrpla;

/// gRPC client code generated from proto/ at build time.
#[allow(clippy::all, clippy::pedantic, missing_debug_implementations)]
pub mod proto {
    tonic::include_proto!("org.xrpl.rpc.v1");
}
