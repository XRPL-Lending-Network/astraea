//! Object key from `ledger_entry` and `proof_entry` params: the selectors of
//! Clio 2.8, with the same key derivation as xrpld (`Indexes.cpp`) and the same
//! error codes as Clio.

use serde_json::{Map, Value};
use witness_core::sha512_half;

use crate::api::{
    Res, account_id, as_u32, currency_code, hash256, invalid_params, keylet, rpc_err,
};

/// Object key and the type expected under it.
pub(crate) type EntryKey = ([u8; 32], Option<&'static str>);
type KeyFn<'a> = &'a dyn Fn(&Map<String, Value>) -> Res<[u8; 32]>;

/// Selectors that also take the object key as a hex string, and the type
/// expected under it, as in Clio.
const BY_INDEX: [(&str, Option<&str>); 26] = [
    ("index", None),
    ("directory", Some("DirectoryNode")),
    ("offer", Some("Offer")),
    ("check", Some("Check")),
    ("escrow", Some("Escrow")),
    ("payment_channel", Some("PayChannel")),
    ("deposit_preauth", Some("DepositPreauth")),
    ("ticket", Some("Ticket")),
    ("nft_page", Some("NFTokenPage")),
    ("amm", Some("AMM")),
    (
        "xchain_owned_create_account_claim_id",
        Some("XChainOwnedCreateAccountClaimID"),
    ),
    ("xchain_owned_claim_id", Some("XChainOwnedClaimID")),
    ("oracle", Some("Oracle")),
    ("credential", Some("Credential")),
    ("mptoken", Some("MPToken")),
    ("permissioned_domain", Some("PermissionedDomain")),
    ("vault", Some("Vault")),
    ("loan_broker", Some("LoanBroker")),
    ("loan", Some("Loan")),
    ("delegate", Some("Delegate")),
    ("amendments", Some("Amendments")),
    ("fee", Some("FeeSettings")),
    ("hashes", Some("LedgerHashes")),
    ("nft_offer", Some("NFTokenOffer")),
    ("nunl", Some("NegativeUNL")),
    ("signer_list", Some("SignerList")),
];

/// Longest `credential_type`, in bytes (`maxCredentialTypeLength` in xrpld).
const MAX_CREDENTIAL_TYPE: usize = 64;
/// Most credentials in `authorized_credentials` (`maxCredentialsArraySize`).
const MAX_CREDENTIALS: usize = 8;

fn malformed() -> crate::api::RpcError {
    rpc_err("malformedRequest", 5001, "Malformed request.")
}

fn malformed_owner() -> crate::api::RpcError {
    rpc_err("malformedOwner", 5002, "Malformed owner.")
}

fn malformed_address() -> crate::api::RpcError {
    rpc_err("malformedAddress", 5003, "Malformed address.")
}

fn malformed_document_id() -> crate::api::RpcError {
    rpc_err("malformedDocumentID", 5007, "Malformed oracle_document_id.")
}

fn malformed_credentials(message: &str) -> crate::api::RpcError {
    rpc_err("malformedAuthorizedCredentials", 5008, message)
}

fn u32_of(v: Option<&Value>) -> Res<u32> {
    v.and_then(as_u32).ok_or_else(malformed)
}

/// Required account field: missing is a malformed request, a bad address is `bad`.
fn account_field(
    o: &Map<String, Value>,
    name: &str,
    bad: fn() -> crate::api::RpcError,
) -> Res<[u8; 20]> {
    account_id(o.get(name).ok_or_else(malformed)?).map_err(|_| bad())
}

fn hex_bytes<const N: usize>(v: Option<&Value>) -> Res<[u8; N]> {
    v.and_then(Value::as_str)
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or_else(malformed)
}

/// Issue from JSON as in `issueFromJson`: XRP without an issuer, any other
/// currency with one.
type Issue = ([u8; 20], [u8; 20]);

fn issue(v: Option<&Value>) -> Res<Issue> {
    let o = v.and_then(Value::as_object).ok_or_else(malformed)?;
    let currency = o
        .get("currency")
        .and_then(Value::as_str)
        .and_then(currency_code)
        .ok_or_else(malformed)?;
    let xrp = currency == [0; 20];
    match (xrp, o.get("issuer")) {
        (true, None) => Ok((currency, [0; 20])),
        (false, Some(i)) => match account_id(i) {
            Ok(a) if a != [0; 20] => Ok((currency, a)),
            _ => Err(malformed()),
        },
        _ => Err(malformed()),
    }
}

/// Ordering of issues in xrpld: by currency, then by issuer unless it is XRP.
fn issue_order(a: &Issue, b: &Issue) -> std::cmp::Ordering {
    a.0.cmp(&b.0).then_with(|| {
        if a.0 == [0; 20] {
            std::cmp::Ordering::Equal
        } else {
            a.1.cmp(&b.1)
        }
    })
}

/// A cross-chain bridge spec: locking door and issue, issuing door and issue.
struct Bridge {
    locking_door: [u8; 20],
    locking_issue: Issue,
    issuing_door: [u8; 20],
    issuing_issue: Issue,
}

fn bridge(o: &Map<String, Value>) -> Res<Bridge> {
    Ok(Bridge {
        locking_door: account_field(o, "LockingChainDoor", malformed)?,
        locking_issue: issue(o.get("LockingChainIssue"))?,
        issuing_door: account_field(o, "IssuingChainDoor", malformed)?,
        issuing_issue: issue(o.get("IssuingChainIssue"))?,
    })
}

fn claim_id_key(space: u8, b: &Bridge, seq: u32) -> [u8; 32] {
    keylet(
        space,
        &[
            &b.locking_door,
            &b.locking_issue.0,
            &b.locking_issue.1,
            &b.issuing_door,
            &b.issuing_issue.0,
            &b.issuing_issue.1,
            &u64::from(seq).to_be_bytes(),
        ],
    )
}

fn credential_type(v: Option<&Value>) -> Res<Vec<u8>> {
    let s = v
        .ok_or_else(malformed)?
        .as_str()
        .ok_or_else(|| malformed_credentials("credential_type NotString"))?;
    let b = hex::decode(s).map_err(|_| malformed_credentials("credential_type NotHexString"))?;
    if b.is_empty() {
        return Err(malformed_credentials("credential_type is empty"));
    }
    if b.len() > MAX_CREDENTIAL_TYPE {
        return Err(malformed_credentials(
            "credential_type greater than max length",
        ));
    }
    Ok(b)
}

/// DepositPreauth key for a set of credentials: each (issuer, type) pair
/// hashed, in sorted order, then their count, as `keylet::depositPreauth`.
fn preauth_credentials_key(owner: &[u8; 20], v: &Value) -> Res<[u8; 32]> {
    let a = v
        .as_array()
        .ok_or_else(|| rpc_err("malformedRequest", 5001, "authorized_credentials not array"))?;
    if a.is_empty() {
        return Err(malformed_credentials(
            "Requires at least one element in authorized_credentials array.",
        ));
    }
    if a.len() > MAX_CREDENTIALS {
        return Err(malformed_credentials(&format!(
            "Max {MAX_CREDENTIALS} number of credentials in authorized_credentials array"
        )));
    }
    let mut set = std::collections::BTreeSet::new();
    for c in a {
        let o = c.as_object().ok_or_else(|| {
            malformed_credentials("authorized_credentials elements in array are not objects.")
        })?;
        let issuer = account_id(
            o.get("issuer")
                .ok_or_else(|| malformed_credentials("Field 'Issuer' is required but missing."))?,
        )
        .map_err(|_| malformed_credentials("issuer NotString"))?;
        if o.get("credential_type").is_none() {
            return Err(malformed_credentials(
                "Field 'CredentialType' is required but missing.",
            ));
        }
        set.insert((issuer, credential_type(o.get("credential_type"))?));
    }
    if set.len() != a.len() {
        return Err(malformed_credentials("duplicates in credentials."));
    }
    let parts: Vec<[u8; 32]> = set
        .iter()
        .map(|(issuer, t)| sha512_half(&[issuer.as_slice(), t].concat()))
        .collect();
    let count = (parts.len() as u64).to_be_bytes();
    let mut fields: Vec<&[u8]> = vec![owner];
    fields.extend(parts.iter().map(|h| &h[..]));
    fields.push(&count);
    Ok(keylet(b'P', &fields))
}

pub(crate) fn entry_key(p: &Map<String, Value>) -> Res<EntryKey> {
    let obj_or_index = |v: &Value, what: &'static str, f: KeyFn<'_>| -> Res<EntryKey> {
        match v {
            Value::String(_) => Ok((
                hash256(v, "ledgerIndex").map_err(|_| malformed())?,
                Some(what),
            )),
            Value::Object(o) => Ok((f(o)?, Some(what))),
            _ => Err(malformed()),
        }
    };
    for (name, expected) in BY_INDEX {
        if let Some(v @ Value::String(_)) = p.get(name) {
            return Ok((
                hash256(v, "ledgerIndex").map_err(|_| malformed())?,
                expected,
            ));
        }
    }
    if let Some(v) = p.get("index") {
        return Ok((hash256(v, "ledgerIndex").map_err(|_| malformed())?, None));
    }
    if let Some(v) = p.get("account_root") {
        return Ok((
            keylet(b'a', &[&account_id(v).map_err(|_| malformed())?]),
            Some("AccountRoot"),
        ));
    }
    if let Some(v) = p.get("did") {
        let a = account_id(v).map_err(|_| malformed_address())?;
        return Ok((keylet(b'I', &[&a]), Some("DID")));
    }
    if let Some(v) = p.get("mpt_issuance") {
        let id: [u8; 24] = hex_bytes(Some(v))?;
        return Ok((keylet(b'~', &[&id]), Some("MPTokenIssuance")));
    }
    for (name, what) in [
        ("check", "Check"),
        ("payment_channel", "PayChannel"),
        ("nft_page", "NFTokenPage"),
        ("amendments", "Amendments"),
        ("fee", "FeeSettings"),
        ("hashes", "LedgerHashes"),
        ("nft_offer", "NFTokenOffer"),
        ("nunl", "NegativeUNL"),
        ("signer_list", "SignerList"),
    ] {
        if let Some(v) = p.get(name) {
            return Ok((
                hash256(v, "ledgerIndex").map_err(|_| malformed())?,
                Some(what),
            ));
        }
    }
    if let Some(v) = p.get("offer") {
        return obj_or_index(v, "Offer", &|o| {
            let a = account_id(o.get("account").ok_or_else(malformed)?).map_err(|_| malformed())?;
            Ok(keylet(b'o', &[&a, &u32_of(o.get("seq"))?.to_be_bytes()]))
        });
    }
    if let Some(v) = p.get("escrow") {
        return obj_or_index(v, "Escrow", &|o| {
            let a = account_id(o.get("owner").ok_or_else(malformed)?).map_err(|_| malformed())?;
            Ok(keylet(b'u', &[&a, &u32_of(o.get("seq"))?.to_be_bytes()]))
        });
    }
    if let Some(v) = p.get("ticket") {
        return obj_or_index(v, "Ticket", &|o| {
            let a = account_id(o.get("account").ok_or_else(malformed)?).map_err(|_| malformed())?;
            Ok(keylet(
                b'T',
                &[&a, &u32_of(o.get("ticket_seq"))?.to_be_bytes()],
            ))
        });
    }
    if let Some(v) = p.get("deposit_preauth") {
        return obj_or_index(v, "DepositPreauth", &|o| {
            let owner =
                account_id(o.get("owner").ok_or_else(malformed)?).map_err(|_| malformed())?;
            match (o.get("authorized"), o.get("authorized_credentials")) {
                (Some(auth), None) => {
                    let auth = account_id(auth).map_err(|_| malformed())?;
                    Ok(keylet(b'p', &[&owner, &auth]))
                }
                (None, Some(creds)) => preauth_credentials_key(&owner, creds),
                _ => Err(rpc_err(
                    "malformedRequest",
                    5001,
                    "Must have one of authorized or authorized_credentials.",
                )),
            }
        });
    }
    if let Some(v) = p.get("ripple_state") {
        let o = v.as_object().ok_or_else(malformed)?;
        let accounts = o
            .get("accounts")
            .and_then(Value::as_array)
            .filter(|a| a.len() == 2)
            .ok_or_else(malformed)?;
        let a = account_id(&accounts[0]).map_err(|_| malformed())?;
        let b = account_id(&accounts[1]).map_err(|_| malformed())?;
        if a == b {
            return Err(malformed());
        }
        let cur = currency_code(
            o.get("currency")
                .and_then(Value::as_str)
                .ok_or_else(malformed)?,
        )
        .ok_or_else(malformed)?;
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        return Ok((keylet(b'r', &[&lo, &hi, &cur]), Some("RippleState")));
    }
    if let Some(v) = p.get("directory") {
        return match v {
            Value::Object(o) => {
                let root = match (o.get("owner"), o.get("dir_root")) {
                    (Some(_), Some(_)) | (None, None) => return Err(malformed()),
                    (Some(owner), None) => {
                        keylet(b'O', &[&account_id(owner).map_err(|_| malformed())?])
                    }
                    (None, Some(r)) => hash256(r, "ledgerIndex").map_err(|_| malformed())?,
                };
                let sub = o
                    .get("sub_index")
                    .map(|v| v.as_u64().ok_or_else(malformed))
                    .transpose()?
                    .unwrap_or(0);
                let key = if sub == 0 {
                    root
                } else {
                    keylet(b'd', &[&root, &sub.to_be_bytes()])
                };
                Ok((key, Some("DirectoryNode")))
            }
            _ => Err(malformed()),
        };
    }
    if let Some(v) = p.get("amm") {
        let o = v.as_object().ok_or_else(malformed)?;
        let a = issue(o.get("asset"))?;
        let b = issue(o.get("asset2"))?;
        let (lo, hi) = if issue_order(&a, &b).is_gt() {
            (b, a)
        } else {
            (a, b)
        };
        return Ok((keylet(b'A', &[&lo.1, &lo.0, &hi.1, &hi.0]), Some("AMM")));
    }
    if let Some(v) = p.get("bridge") {
        let b = bridge(v.as_object().ok_or_else(malformed)?)?;
        let door =
            account_id(p.get("bridge_account").ok_or_else(malformed)?).map_err(|_| malformed())?;
        let (door, issue) = if door == b.locking_door {
            (b.locking_door, b.locking_issue)
        } else if door == b.issuing_door {
            (b.issuing_door, b.issuing_issue)
        } else {
            return Err(malformed());
        };
        return Ok((keylet(b'H', &[&door, &issue.0]), Some("Bridge")));
    }
    for (name, space, what) in [
        ("xchain_owned_claim_id", b'Q', "XChainOwnedClaimID"),
        (
            "xchain_owned_create_account_claim_id",
            b'K',
            "XChainOwnedCreateAccountClaimID",
        ),
    ] {
        if let Some(v) = p.get(name) {
            let o = v.as_object().ok_or_else(malformed)?;
            let b = bridge(o)?;
            return Ok((claim_id_key(space, &b, u32_of(o.get(name))?), Some(what)));
        }
    }
    if let Some(v) = p.get("oracle") {
        let o = v.as_object().ok_or_else(malformed)?;
        let a = account_field(o, "account", malformed_address)?;
        let id = o.get("oracle_document_id").ok_or_else(malformed)?;
        let id = as_u32(id).ok_or_else(malformed_document_id)?;
        return Ok((keylet(b'R', &[&a, &id.to_be_bytes()]), Some("Oracle")));
    }
    if let Some(v) = p.get("credential") {
        let o = v.as_object().ok_or_else(malformed)?;
        let subject = account_field(o, "subject", malformed_address)?;
        let issuer = account_field(o, "issuer", malformed_address)?;
        let t = credential_type(o.get("credential_type"))?;
        return Ok((keylet(b'D', &[&subject, &issuer, &t]), Some("Credential")));
    }
    if let Some(v) = p.get("mptoken") {
        let o = v.as_object().ok_or_else(malformed)?;
        let holder = account_field(o, "account", malformed_address)?;
        let id: [u8; 24] = hex_bytes(Some(o.get("mpt_issuance_id").ok_or_else(malformed)?))?;
        let issuance = keylet(b'~', &[&id]);
        return Ok((keylet(b't', &[&issuance, &holder]), Some("MPToken")));
    }
    type BadAccount = fn() -> crate::api::RpcError;
    let by_owner: [(&str, &str, BadAccount, u8, &'static str); 3] = [
        (
            "permissioned_domain",
            "account",
            malformed_address,
            b'm',
            "PermissionedDomain",
        ),
        ("vault", "owner", malformed_owner, b'V', "Vault"),
        ("loan_broker", "owner", malformed_owner, b'l', "LoanBroker"),
    ];
    for (name, owner, bad, space, what) in by_owner {
        if let Some(v) = p.get(name) {
            let o = v.as_object().ok_or_else(malformed)?;
            let seq = u32_of(o.get("seq"))?;
            let a = account_field(o, owner, bad)?;
            return Ok((keylet(space, &[&a, &seq.to_be_bytes()]), Some(what)));
        }
    }
    if let Some(v) = p.get("loan") {
        let o = v.as_object().ok_or_else(malformed)?;
        let seq = u32_of(o.get("loan_seq"))?;
        let broker: [u8; 32] = hex_bytes(Some(o.get("loan_broker_id").ok_or_else(malformed)?))?;
        return Ok((keylet(b'L', &[&broker, &seq.to_be_bytes()]), Some("Loan")));
    }
    if let Some(v) = p.get("delegate") {
        let o = v.as_object().ok_or_else(malformed)?;
        let a = account_field(o, "account", malformed_address)?;
        let auth = account_field(o, "authorize", malformed_address)?;
        return Ok((keylet(b'E', &[&a, &auth]), Some("Delegate")));
    }
    Err(invalid_params("No ledger_entry params provided."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
    const B: &str = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
    const MPT: &str = "00000005B5F762798A53D543A014CAF8B297CFF8F2F937E8";

    fn key(p: Value) -> String {
        hex::encode_upper(entry_key(p.as_object().unwrap()).unwrap().0)
    }

    fn error(p: Value) -> &'static str {
        entry_key(p.as_object().unwrap()).unwrap_err().error
    }

    fn bridge_spec() -> Value {
        json!({
            "LockingChainDoor": A, "LockingChainIssue": {"currency": "XRP"},
            "IssuingChainDoor": B, "IssuingChainIssue": {"currency": "XRP"},
        })
    }

    /// Keys that xrpld 3.4.1 returns in `index` for the same params.
    #[test]
    fn keys_match_xrpld() {
        let cases = [
            (
                json!({"vault": {"owner": A, "seq": 5}}),
                "61B03A6F8CEBD3AF9D8F696C3D0A9A9F0493B34BF6B5D93CF0BC009E6BA75303",
            ),
            (
                json!({"loan_broker": {"owner": A, "seq": 7}}),
                "BBCBB73FD61614BFCD4F5CEF761F5BFD38D39AB13D71C76FA0C02527640B0583",
            ),
            (
                json!({"loan": {"loan_broker_id": "61B03A6F8CEBD3AF9D8F696C3D0A9A9F0493B34BF6B5D93CF0BC009E6BA75303", "loan_seq": 3}}),
                "62B4C15A02EE5072CE2FEC01DF94ED1AD51CB5676D764035B513832E9604ADE5",
            ),
            (
                json!({"mpt_issuance": MPT}),
                "8AD74F33EF13BD12BBDC4CD8B439C28B665A11ED713720342EDEE5EEFBB9C37F",
            ),
            (
                json!({"mptoken": {"mpt_issuance_id": MPT, "account": B}}),
                "4FF33B3FFE1CF2351281016B7C1FEDBA673455CEA77F966CE4B7E6A08E7DB366",
            ),
            (
                json!({"credential": {"subject": A, "issuer": B, "credential_type": "4B5943"}}),
                "EAE038707C2706638B6B5BC9B4B9562691558023EE99D7B47FEE2B1EA83677B8",
            ),
            (
                json!({"amm": {"asset": {"currency": "XRP"}, "asset2": {"currency": "USD", "issuer": B}}}),
                "FB7275EDC1C45EA2C6C1BB7D312D1EC35367EF11A2BD3C666636260F45A4A3A1",
            ),
            (
                json!({"amm": {"asset": {"currency": "USD", "issuer": B}, "asset2": {"currency": "EUR", "issuer": A}}}),
                "0E64078DB3F56C386DDD0BC07C4AAACAE13A537B6250F48D951C72A4F66ED2D7",
            ),
            (
                json!({"oracle": {"account": A, "oracle_document_id": 1}}),
                "08198EB44C3FEABCC015AE1C1DB979CF3B057DB25D72F0C65372873F30242C27",
            ),
            (
                json!({"did": A}),
                "5D71AD4469C5444C5FBAAFCF6DAE6E625D32F74995098F4FEF3E0B0F7B36B8F9",
            ),
            (
                json!({"delegate": {"account": A, "authorize": B}}),
                "0482B042D3E6F399BD2723FB6119FBAF953FB76CDF2C90EE9A7063749A27E025",
            ),
            (
                json!({"permissioned_domain": {"account": A, "seq": 9}}),
                "34925625D499391E57C6E8B2F8A3DD9B737AC08ECBC76BB1F0699A0C610ECAB4",
            ),
            (
                json!({"deposit_preauth": {"owner": A, "authorized_credentials": [
                    {"issuer": B, "credential_type": "4B5943"},
                    {"issuer": A, "credential_type": "4B59"},
                ]}}),
                "51F92695EDA6528BFB4B3DFDA69AEA1A0CBDDDE5A316F5960EC085F16DAB5C59",
            ),
            (
                json!({"bridge_account": A, "bridge": bridge_spec()}),
                "20C736B81A2632BE6A0FCE130FC3649334A041B79C6017896709F39B6059DB92",
            ),
            (
                json!({"bridge_account": B, "bridge": bridge_spec()}),
                "5CE45F9906FC077A90654A76C4B60302CC2F75ACE80F8DC8BCA7482AE782EA74",
            ),
        ];
        for (p, want) in cases {
            assert_eq!(key(p.clone()), want, "{p}");
        }
        let mut claim = bridge_spec();
        claim["xchain_owned_claim_id"] = json!(4);
        assert_eq!(
            key(json!({ "xchain_owned_claim_id": claim })),
            "4572D0B7D88AD04711A8E00B0F6F1764B2F3952CE1C759985E7392BB14322DFA"
        );
        let mut create = bridge_spec();
        create["xchain_owned_create_account_claim_id"] = json!(6);
        assert_eq!(
            key(json!({ "xchain_owned_create_account_claim_id": create })),
            "BFE7E3A09967690BAB18194FCDE0D4649DAFC6F5326E3979A39AF278F3B35176"
        );
    }

    /// Objects from mainnet: the key rebuilt from their fields is their index.
    #[test]
    fn keys_of_mainnet_objects() {
        assert_eq!(
            key(json!({"amm": {
                "asset": {"currency": "XRP"},
                "asset2": {"currency": "515A696C6C610000000000000000000000000000", "issuer": "rUwZzhDKFLcgK87jeJumy5sfLk3XXKUDWh"},
            }})),
            "A931DB0A7848CD26AF18EE1E8BEE237E784B6A381DEFA8044178CBED6EE2610E"
        );
        assert_eq!(
            key(
                json!({"oracle": {"account": "rBXBXd8EZZF1h8848DyMssBZLBZrkBcSY6", "oracle_document_id": 1}})
            ),
            "CA1541B152B286AE9780636AA08E79B7CB7B687D06F62F525CBDDAC62C4D6A31"
        );
    }

    #[test]
    fn hex_strings_select_by_index_with_a_type() {
        let k = "61B03A6F8CEBD3AF9D8F696C3D0A9A9F0493B34BF6B5D93CF0BC009E6BA75303";
        for (name, what) in [
            ("vault", "Vault"),
            ("loan", "Loan"),
            ("amendments", "Amendments"),
            ("signer_list", "SignerList"),
            ("credential", "Credential"),
        ] {
            let (got, t) = entry_key(json!({ name: k }).as_object().unwrap()).unwrap();
            assert_eq!(hex::encode_upper(got), k);
            assert_eq!(t, Some(what));
        }
    }

    #[test]
    fn errors_as_in_clio() {
        assert_eq!(
            error(json!({"vault": {"owner": "x", "seq": 1}})),
            "malformedOwner"
        );
        assert_eq!(error(json!({"vault": {"owner": A}})), "malformedRequest");
        assert_eq!(
            error(json!({"oracle": {"account": A, "oracle_document_id": "x"}})),
            "malformedDocumentID"
        );
        assert_eq!(
            error(json!({"delegate": {"account": A, "authorize": "x"}})),
            "malformedAddress"
        );
        assert_eq!(
            error(json!({"amm": {"asset": {"currency": "USD"}, "asset2": {"currency": "XRP"}}})),
            "malformedRequest"
        );
        assert_eq!(
            error(json!({"deposit_preauth": {"owner": A, "authorized_credentials": []}})),
            "malformedAuthorizedCredentials"
        );
        assert_eq!(
            error(
                json!({"deposit_preauth": {"owner": A, "authorized_credentials": [
                    {"issuer": B, "credential_type": "4B"}, {"issuer": B, "credential_type": "4B"},
                ]}})
            ),
            "malformedAuthorizedCredentials"
        );
        assert_eq!(
            error(
                json!({"deposit_preauth": {"owner": A, "authorized": B, "authorized_credentials": []}})
            ),
            "malformedRequest"
        );
        assert_eq!(error(json!({"bridge": bridge_spec()})), "malformedRequest");
        assert_eq!(
            error(
                json!({"bridge_account": "rrrrrrrrrrrrrrrrrrrrrhoLvTp", "bridge": bridge_spec()})
            ),
            "malformedRequest"
        );
        assert_eq!(error(json!({"mpt_issuance": "00"})), "malformedRequest");
        assert_eq!(error(json!({"binary": true})), "invalidParams");
    }
}
