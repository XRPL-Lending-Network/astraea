//! A whole ledger: header, transactions with metadata, state changes.
//! Verification and serialization.
//!
//! Serialization for the log, numbers are little-endian:
//!
//! ```text
//! header (118 bytes)
//! u32 transaction count; for each: u32 tx length, tx, u32 meta length, meta
//! u32 object count; for each: key (32), u8 change type,
//!     u32 data length, data (0 for a deleted object)
//! ```

use witness_core::ledger::{HEADER_LEN, LedgerHeader};
use witness_core::shamap::{has_duplicates, root, tx_id, tx_leaf_hash};

/// How a state object changed in this ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Created = 1,
    Modified = 2,
    Deleted = 3,
}

impl Change {
    pub fn from_u8(b: u8) -> Option<Change> {
        match b {
            1 => Some(Change::Created),
            2 => Some(Change::Modified),
            3 => Some(Change::Deleted),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateChange {
    pub key: [u8; 32],
    pub change: Change,
    /// The object after the change; empty for a deleted one.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    pub header: Vec<u8>,
    pub transactions: Vec<(Vec<u8>, Vec<u8>)>,
    pub changes: Vec<StateChange>,
}

impl Ledger {
    pub fn header(&self) -> Result<LedgerHeader, String> {
        LedgerHeader::parse(&self.header).map_err(|e| e.to_string())
    }

    /// Checks that the transaction tree matches the root in the header. Returns
    /// the parsed header.
    pub fn verify(&self) -> Result<LedgerHeader, String> {
        let h = self.header()?;
        let items: Vec<_> = self
            .transactions
            .iter()
            .map(|(tx, meta)| {
                let id = tx_id(tx);
                (id, tx_leaf_hash(tx, meta, &id))
            })
            .collect();
        if has_duplicates(&items) {
            return Err(format!(
                "ledger {}: duplicate transaction, no tree exists for such a set",
                h.sequence
            ));
        }
        if root(&items) != h.transaction_hash {
            return Err(format!(
                "ledger {}: transaction tree does not match the header",
                h.sequence
            ));
        }
        Ok(h)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.header.len()
                + self
                    .transactions
                    .iter()
                    .map(|(t, m)| t.len() + m.len() + 8)
                    .sum::<usize>()
                + self
                    .changes
                    .iter()
                    .map(|c| c.data.len() + 37)
                    .sum::<usize>()
                + 8,
        );
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&(self.transactions.len() as u32).to_le_bytes());
        for (tx, meta) in &self.transactions {
            out.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            out.extend_from_slice(tx);
            out.extend_from_slice(&(meta.len() as u32).to_le_bytes());
            out.extend_from_slice(meta);
        }
        out.extend_from_slice(&(self.changes.len() as u32).to_le_bytes());
        for c in &self.changes {
            out.extend_from_slice(&c.key);
            out.push(c.change as u8);
            out.extend_from_slice(&(c.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&c.data);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Ledger, String> {
        let mut r = Reader { b, at: 0 };
        let header = r.take(HEADER_LEN)?.to_vec();
        let n = r.u32()?;
        let mut transactions = Vec::with_capacity(n.min(100_000));
        for _ in 0..n {
            let l = r.u32()?;
            let tx = r.take(l)?.to_vec();
            let l = r.u32()?;
            let meta = r.take(l)?.to_vec();
            transactions.push((tx, meta));
        }
        let n = r.u32()?;
        let mut changes = Vec::with_capacity(n.min(1_000_000));
        for _ in 0..n {
            let key: [u8; 32] = r.take(32)?.try_into().map_err(|_| "key")?;
            let change = Change::from_u8(r.take(1)?[0]).ok_or("unknown change type")?;
            let l = r.u32()?;
            let data = r.take(l)?.to_vec();
            changes.push(StateChange { key, change, data });
        }
        if r.at != b.len() {
            return Err("trailing bytes after the ledger".into());
        }
        Ok(Ledger {
            header,
            transactions,
            changes,
        })
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let s = self
            .b
            .get(self.at..self.at + n)
            .ok_or_else(|| format!("ledger truncated at offset {}", self.at))?;
        self.at += n;
        Ok(s)
    }

    fn u32(&mut self) -> Result<usize, String> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two identical transactions used to crash tree construction by indexing
    /// past the key.
    #[test]
    fn duplicate_transaction_is_an_error() {
        let l = Ledger {
            header: vec![0; HEADER_LEN],
            transactions: vec![(vec![1, 2, 3], vec![4]), (vec![1, 2, 3], vec![4])],
            changes: Vec::new(),
        };
        assert!(l.verify().unwrap_err().contains("duplicate"));
    }

    #[test]
    fn roundtrip() {
        let l = Ledger {
            header: vec![7; HEADER_LEN],
            transactions: vec![(vec![1, 2, 3], vec![4, 5]), (vec![], vec![6])],
            changes: vec![
                StateChange {
                    key: [9; 32],
                    change: Change::Modified,
                    data: vec![1; 10],
                },
                StateChange {
                    key: [8; 32],
                    change: Change::Deleted,
                    data: vec![],
                },
            ],
        };
        let b = l.encode();
        assert_eq!(Ledger::decode(&b).unwrap(), l);
        assert!(Ledger::decode(&b[..b.len() - 1]).is_err());
        let mut longer = b.clone();
        longer.push(0);
        assert!(Ledger::decode(&longer).is_err());
    }

    #[test]
    fn wrong_transactions_fail_verification() {
        // A header with a zero transaction root and one transaction.
        let l = Ledger {
            header: vec![0; HEADER_LEN],
            transactions: vec![(vec![1], vec![2])],
            changes: vec![],
        };
        assert!(l.verify().is_err());
        let empty = Ledger {
            header: vec![0; HEADER_LEN],
            transactions: vec![],
            changes: vec![],
        };
        // An empty tree has a zero root, so it matches.
        assert!(empty.verify().is_ok());
    }
}
