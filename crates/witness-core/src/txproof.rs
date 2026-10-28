//! A transaction inclusion proof as a portable object.
//!
//! It holds the ledger header, the transaction, the metadata and the path in
//! the transaction tree. Verification answers the question "this transaction
//! with this metadata is recorded in the ledger with such-and-such hash".
//! Whether the network confirmed that ledger hash is a separate question,
//! settled by the quorum over the evidence bundle (`evidence`). The two
//! claims are kept apart.

use serde::{Deserialize, Serialize};

use crate::ledger::LedgerHeader;
use crate::shamap::{Hash, Path, tx_id, tx_leaf_hash, verify};

pub const FORMAT: &str = "xrpl-witness/tx-proof/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxProof {
    pub format: String,
    /// Ledger header, 118 bytes in hex.
    pub ledger_header: String,
    /// Transaction and metadata in hex, byte for byte.
    pub tx: String,
    pub meta: String,
    /// Inner nodes from the root down: 16 child hashes each, in hex.
    pub path: Vec<Vec<String>>,
}

/// What the proof establishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Proven {
    pub tx_hash: String,
    pub ledger_index: u32,
    /// Hash of the ledger the transaction is recorded in. Whether a quorum
    /// confirmed it is checked separately.
    pub ledger_hash: String,
}

impl TxProof {
    pub fn new(header: &[u8], tx: &[u8], meta: &[u8], path: &Path) -> TxProof {
        TxProof {
            format: FORMAT.into(),
            ledger_header: hex::encode_upper(header),
            tx: hex::encode_upper(tx),
            meta: hex::encode_upper(meta),
            path: path
                .levels
                .iter()
                .map(|l| l.iter().map(hex::encode_upper).collect())
                .collect(),
        }
    }

    pub fn verify(&self) -> Result<Proven, String> {
        if self.format != FORMAT {
            return Err(format!("format {}, expected {FORMAT}", self.format));
        }
        let dec = |s: &str, what: &str| hex::decode(s).map_err(|_| format!("{what} is not hex"));
        let header =
            LedgerHeader::parse(&dec(&self.ledger_header, "header")?).map_err(|e| e.to_string())?;
        let tx = dec(&self.tx, "transaction")?;
        let meta = dec(&self.meta, "metadata")?;
        let mut levels = Vec::with_capacity(self.path.len());
        for level in &self.path {
            if level.len() != 16 {
                return Err("path node is not 16 hashes".into());
            }
            let mut node = [[0u8; 32]; 16];
            for (slot, h) in node.iter_mut().zip(level) {
                *slot = dec(h, "node hash")?
                    .try_into()
                    .map_err(|_| "node hash is not 32 bytes".to_string())?;
            }
            levels.push(node);
        }
        let key: Hash = tx_id(&tx);
        let leaf = tx_leaf_hash(&tx, &meta, &key);
        if !verify(&Path { levels }, &key, &leaf, &header.transaction_hash) {
            return Err("path does not match the header transaction root".into());
        }
        Ok(Proven {
            tx_hash: hex::encode_upper(key),
            ledger_index: header.sequence,
            ledger_hash: hex::encode_upper(header.hash()),
        })
    }
}
