//! Ledger source: xrpld gRPC, as in Clio.
//!
//! `GetLedger` with transactions and objects returns, in one request, the header,
//! all transactions with metadata, and the state changes relative to the
//! previous ledger. Without rate limits only for hosts listed in
//! `secure_gateway` in the xrpld config; the `user` field is needed for the same reason.

use tonic::transport::{Channel, Endpoint};
use witness_core::ledger::{HEADER_LEN, LedgerHeader};

use crate::ledger::{Change, Ledger, StateChange};
use crate::proto::get_ledger_response::Transactions;
use crate::proto::ledger_specifier::{Ledger as Spec, Shortcut};
use crate::proto::raw_ledger_object::ModificationType;
use crate::proto::xrp_ledger_api_service_client::XrpLedgerApiServiceClient;
use crate::proto::{GetLedgerDataRequest, GetLedgerRequest, LedgerSpecifier};

/// A message with a full ledger can be tens of megabytes.
const MAX_MESSAGE: usize = 256 << 20;

/// Header from gRPC: xrpld appends the ledger hash (32 bytes) to the 118-byte
/// header. We cut it off and compare it with the hash we compute ourselves; we
/// don't take the node's word for it.
fn split_header(raw: Vec<u8>) -> Result<Vec<u8>, String> {
    match raw.len() {
        HEADER_LEN => Ok(raw),
        n if n == HEADER_LEN + 32 => {
            let header = raw[..HEADER_LEN].to_vec();
            let h = LedgerHeader::parse(&header).map_err(|e| e.to_string())?;
            if h.hash()[..] != raw[HEADER_LEN..] {
                return Err(format!(
                    "ledger {}: hash from the node does not match the computed one",
                    h.sequence
                ));
            }
            Ok(header)
        }
        n => Err(format!("ledger header from the node is {n} bytes")),
    }
}

#[derive(Debug, Clone)]
pub struct Source {
    client: XrpLedgerApiServiceClient<Channel>,
    user: String,
}

impl Source {
    pub async fn connect(url: &str, user: &str) -> Result<Source, String> {
        let channel = Endpoint::from_shared(url.to_owned())
            .map_err(|e| format!("address {url}: {e}"))?
            .connect()
            .await
            .map_err(|e| format!("connecting to {url}: {e}"))?;
        Ok(Source {
            client: XrpLedgerApiServiceClient::new(channel).max_decoding_message_size(MAX_MESSAGE),
            user: user.to_owned(),
        })
    }

    async fn get(
        &mut self,
        spec: Spec,
        full: bool,
    ) -> Result<crate::proto::GetLedgerResponse, String> {
        let req = GetLedgerRequest {
            ledger: Some(LedgerSpecifier { ledger: Some(spec) }),
            transactions: full,
            expand: full,
            get_objects: full,
            user: self.user.clone(),
            ..Default::default()
        };
        self.client
            .get_ledger(req)
            .await
            .map(tonic::Response::into_inner)
            .map_err(|e| format!("GetLedger: {} {}", e.code(), e.message()))
    }

    /// Ledger state objects with keys strictly greater than `marker` and strictly
    /// less than `end` (empty means unbounded). Returns the objects and a
    /// continuation marker; an empty marker means the range is exhausted.
    pub async fn state_page(
        &mut self,
        sequence: u32,
        marker: &[u8],
        end: &[u8],
    ) -> Result<(Vec<([u8; 32], Vec<u8>)>, Vec<u8>), String> {
        let req = GetLedgerDataRequest {
            ledger: Some(LedgerSpecifier {
                ledger: Some(Spec::Sequence(sequence)),
            }),
            marker: marker.to_vec(),
            end_marker: end.to_vec(),
            user: self.user.clone(),
            ..Default::default()
        };
        let r = self
            .client
            .get_ledger_data(req)
            .await
            .map(tonic::Response::into_inner)
            .map_err(|e| format!("GetLedgerData: {} {}", e.code(), e.message()))?;
        // xrpld does not fill in the sequence in GetLedgerData responses (checked on 3.4.1),
        // so we reject only if it is present and different. Objects from another ledger
        // would fail anyway: the state root is checked against the header.
        if r.ledger_index != 0 && r.ledger_index != sequence {
            return Err(format!(
                "asked for {sequence}, node returned {} ({} objects, hash {} bytes, marker {} bytes)",
                r.ledger_index,
                r.ledger_objects.as_ref().map_or(0, |o| o.objects.len()),
                r.ledger_hash.len(),
                r.marker.len()
            ));
        }
        let mut out = Vec::new();
        for o in r.ledger_objects.map(|x| x.objects).unwrap_or_default() {
            let key: [u8; 32] = o
                .key
                .as_slice()
                .try_into()
                .map_err(|_| "object key is not 32 bytes".to_string())?;
            out.push((key, o.data));
        }
        Ok((out, r.marker))
    }

    /// Ledger header (118 bytes) without transactions.
    pub async fn header(&mut self, sequence: u32) -> Result<Vec<u8>, String> {
        let r = self.get(Spec::Sequence(sequence), false).await?;
        if !r.validated {
            return Err(format!("ledger {sequence} is not validated on the node"));
        }
        split_header(r.ledger_header)
    }

    /// Requires the node to exempt us from rate limits
    /// (`is_unlimited` in the response).
    ///
    /// xrpld charges by address, not by client: without the exemption, heavy
    /// requests are charged to an address shared with neighboring services.
    ///
    /// The exemption alone is not enough. A state snapshot taken on a machine
    /// running Clio had the exemption but still loaded the machine: 4.8 GB in
    /// 3.6 minutes over a tunnel and onto disk. Clio fell behind reading its
    /// subscriptions, both upstream nodes treated it as a slow client and dropped
    /// it, and it went down twice. Don't run heavy jobs on a machine running Clio.
    pub async fn require_unlimited(&mut self) -> Result<(), String> {
        let r = self
            .get(Spec::Shortcut(Shortcut::Validated as i32), false)
            .await?;
        if r.is_unlimited {
            Ok(())
        } else {
            Err(
                "node does not exempt us from rate limits (is_unlimited = false): \
                 charges will go to the shared address and get neighboring services disconnected; \
                 check secure_gateway in [port_grpc] and the user field"
                    .into(),
            )
        }
    }

    /// Sequence of the latest validated ledger.
    pub async fn validated(&mut self) -> Result<u32, String> {
        let r = self
            .get(Spec::Shortcut(Shortcut::Validated as i32), false)
            .await?;
        let h = LedgerHeader::parse(&split_header(r.ledger_header)?).map_err(|e| e.to_string())?;
        Ok(h.sequence)
    }

    /// The whole ledger. Fails if the node does not consider it validated or
    /// did not return the state changes.
    pub async fn ledger(&mut self, sequence: u32) -> Result<Ledger, String> {
        let r = self.get(Spec::Sequence(sequence), true).await?;
        if !r.validated {
            return Err(format!("ledger {sequence} is not validated on the node"));
        }
        if !r.objects_included {
            return Err(format!(
                "node did not return state changes for ledger {sequence}"
            ));
        }
        let transactions = match r.transactions {
            Some(Transactions::TransactionsList(l)) => l
                .transactions
                .into_iter()
                .map(|t| (t.transaction_blob, t.metadata_blob))
                .collect(),
            Some(Transactions::HashesList(_)) => {
                return Err("node returned hashes instead of transactions".into());
            }
            None => Vec::new(),
        };
        let mut changes = Vec::new();
        for o in r.ledger_objects.map(|x| x.objects).unwrap_or_default() {
            let key: [u8; 32] = o
                .key
                .as_slice()
                .try_into()
                .map_err(|_| "object key is not 32 bytes".to_string())?;
            let change = match ModificationType::try_from(o.mod_type) {
                Ok(ModificationType::Created) => Change::Created,
                Ok(ModificationType::Deleted) => Change::Deleted,
                Ok(ModificationType::Modified) => Change::Modified,
                // Older xrpld versions don't mark the type: a deleted object has no data.
                _ if o.data.is_empty() => Change::Deleted,
                _ => Change::Modified,
            };
            changes.push(StateChange {
                key,
                change,
                data: o.data,
            });
        }
        Ok(Ledger {
            header: split_header(r.ledger_header)?,
            transactions,
            changes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_header_with_appended_hash_is_checked() {
        let header = vec![1u8; HEADER_LEN];
        let hash = LedgerHeader::parse(&header).unwrap().hash();
        let mut raw = header.clone();
        raw.extend_from_slice(&hash);
        assert_eq!(split_header(raw.clone()).unwrap(), header);
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(split_header(raw).is_err());
        assert_eq!(split_header(header.clone()).unwrap(), header);
        assert!(split_header(vec![0; 100]).is_err());
    }
}
