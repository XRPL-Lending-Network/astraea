//! Ledger indexes: transaction by hash, ledger by hash, account history.
//!
//! A transaction's accounts follow the same rule as `TxMeta::getAffectedAccounts`
//! in xrpld (which Clio also uses for account_tx): for every affected
//! object take the top-level fields from FinalFields, or from NewFields for a
//! created one; the history gets every account field, plus the issuers of LowLimit,
//! HighLimit, TakerPays, TakerGets and the issuer of MPTokenIssuanceID.

use witness_core::shamap::tx_id;
use witness_core::stobject::{self, Field, FieldId, types};

use crate::ledger::Ledger;

const AFFECTED_NODES: FieldId = FieldId::new(types::ARRAY, 8);
const CREATED_NODE: FieldId = FieldId::new(types::OBJECT, 3);
const FINAL_FIELDS: FieldId = FieldId::new(types::OBJECT, 7);
const NEW_FIELDS: FieldId = FieldId::new(types::OBJECT, 8);
const TRANSACTION_INDEX: FieldId = FieldId::new(types::UINT32, 28);
const TAKER_PAYS: FieldId = FieldId::new(types::AMOUNT, 4);
const TAKER_GETS: FieldId = FieldId::new(types::AMOUNT, 5);
const LOW_LIMIT: FieldId = FieldId::new(types::AMOUNT, 6);
const HIGH_LIMIT: FieldId = FieldId::new(types::AMOUNT, 7);
const MPT_ISSUANCE_ID: FieldId = FieldId::new(types::HASH192, 1);

pub type AccountId = [u8; 20];

/// A transaction in the indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEntry {
    pub id: [u8; 32],
    /// Position in the ledger's transaction list, as stored in the block.
    pub pos: u32,
    /// TransactionIndex from the metadata: order of application in the ledger.
    pub index: u32,
    pub accounts: Vec<AccountId>,
}

/// Accounts affected by a transaction, and its TransactionIndex.
pub fn affected_accounts(meta: &[u8]) -> Result<(u32, Vec<AccountId>), String> {
    let fields = stobject::fields(meta).map_err(|e| format!("metadata: {e}"))?;
    let index = stobject::find(&fields, TRANSACTION_INDEX)
        .and_then(stobject::u32_of)
        .ok_or("no TransactionIndex in metadata")?;
    let mut out: Vec<AccountId> = Vec::new();
    let mut add = |a: &[u8]| {
        if let Ok(a) = <AccountId>::try_from(a)
            && a != [0; 20]
        {
            out.push(a);
        }
    };
    let nodes = fields
        .iter()
        .find(|f| f.id == AFFECTED_NODES)
        .ok_or("no AffectedNodes in metadata")?;
    for node in stobject::children(nodes).map_err(|e| e.to_string())? {
        let want = if node.id == CREATED_NODE {
            NEW_FIELDS
        } else {
            FINAL_FIELDS
        };
        let inner = stobject::children(&node).map_err(|e| e.to_string())?;
        let Some(inner) = inner.iter().find(|f| f.id == want) else {
            continue;
        };
        for f in stobject::children(inner).map_err(|e| e.to_string())? {
            issuer_or_account(&f, &mut add);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok((index, out))
}

fn issuer_or_account(f: &Field<'_>, add: &mut impl FnMut(&[u8])) {
    if f.id.type_code == types::ACCOUNT {
        add(f.value);
    } else if [LOW_LIMIT, HIGH_LIMIT, TAKER_PAYS, TAKER_GETS].contains(&f.id) {
        // An issued currency amount is 48 bytes, the issuer is the last 20. XRP
        // has no issuer; MPT never appears in these fields.
        if f.value.len() == 48 {
            add(&f.value[28..]);
        }
    } else if f.id == MPT_ISSUANCE_ID && f.value.len() == 24 {
        // MPTID: issuance sequence (4 bytes) and the issuer.
        add(&f.value[4..]);
    }
}

/// Index entries for a ledger.
pub fn entries(ledger: &Ledger) -> Result<Vec<TxEntry>, String> {
    ledger
        .transactions
        .iter()
        .enumerate()
        .map(|(pos, (tx, meta))| {
            let (index, accounts) = affected_accounts(meta)?;
            Ok(TxEntry {
                id: tx_id(tx),
                pos: pos as u32,
                index,
                accounts,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_field(code: u8, a: u8) -> Vec<u8> {
        // Type 8, field code, length 20.
        let mut v = vec![0x80 | code, 20];
        v.extend([a; 20]);
        v
    }

    fn node(kind: u8, inner_kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0xE0 | kind, 0xE0 | inner_kind];
        v.extend(body);
        v.extend([0xE1, 0xE1]);
        v
    }

    #[test]
    fn accounts_follow_xrpld_rule() {
        // Modified object: Account (8,1) in FinalFields, and in PreviousFields
        // a different account that does not count.
        let mut modified = vec![0xE5, 0xE6];
        modified.extend(account_field(1, 9));
        modified.push(0xE1);
        modified.push(0xE7);
        modified.extend(account_field(1, 1));
        // HighLimit (6,7): issued currency with issuer 2.
        modified.extend([0x67, 0x80 | 0x40]);
        modified.extend([0u8; 7 + 20]);
        modified.extend([2u8; 20]);
        modified.extend([0xE1, 0xE1]);
        // Created object: Destination (8,3) in NewFields.
        let created = node(3, 8, &account_field(3, 3));
        // Deleted object: FinalFields; a zero account does not count.
        let deleted = node(4, 7, &account_field(1, 0));

        let mut meta = vec![0x20, 0x1C, 0, 0, 0, 5]; // TransactionIndex = 5
        meta.push(0xF8); // AffectedNodes
        meta.extend(modified);
        meta.extend(created);
        meta.extend(deleted);
        meta.push(0xF1);
        let (index, accounts) = affected_accounts(&meta).unwrap();
        assert_eq!(index, 5);
        assert_eq!(accounts, vec![[1; 20], [2; 20], [3; 20]]);
    }
}
