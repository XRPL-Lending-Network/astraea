//! The Negative UNL object in ledger state.
//!
//! The network itself temporarily disables UNL validators that have not
//! taken part in consensus for a long time, so their silence does not get in
//! the way of reaching quorum. The list of disabled validators lives in the
//! ledger as a single object with a fixed index and changes only in flag
//! ledgers (every 256).
//!
//! Besides the disabled ones, the object can carry candidates: who will be
//! disabled and who will be re-enabled at the next flag ledger. They do not
//! affect the quorum of the current ledger but matter for history.

use crate::stobject::{self, Error, fields as f};

/// Index of the Negative UNL object, one per ledger.
pub const INDEX: &str = "2E8A59AA9D3B5B186B0B9E0F62E6C02587CA74A4D778938E957B6357D364B244";

/// Ledger entry type `NegativeUNL`: the letter N.
const ENTRY_TYPE: u16 = 0x004E;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disabled {
    /// Master key of the disabled validator.
    pub master_key: Vec<u8>,
    /// The ledger it has been disabled since.
    pub since: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegativeUnl {
    pub disabled: Vec<Disabled>,
    pub to_disable: Option<Vec<u8>>,
    pub to_re_enable: Option<Vec<u8>>,
}

impl NegativeUnl {
    pub fn parse(raw: &[u8]) -> Result<NegativeUnl, Error> {
        let fs = stobject::fields(raw)?;
        let kind = stobject::find(&fs, f::LEDGER_ENTRY_TYPE)
            .and_then(|v| <[u8; 2]>::try_from(v).ok())
            .map(u16::from_be_bytes);
        if kind != Some(ENTRY_TYPE) {
            return Err(Error::Malformed("not a NegativeUNL object".into()));
        }
        let mut disabled = Vec::new();
        if let Some(arr) = fs.iter().find(|x| x.id == f::DISABLED_VALIDATORS) {
            for item in stobject::children(arr)? {
                if item.id != f::DISABLED_VALIDATOR {
                    return Err(Error::Malformed(
                        "unexpected element in DisabledValidators".into(),
                    ));
                }
                let inner = stobject::children(&item)?;
                disabled.push(Disabled {
                    master_key: stobject::find(&inner, f::PUBLIC_KEY)
                        .ok_or_else(|| Error::Malformed("missing PublicKey".into()))?
                        .to_vec(),
                    since: stobject::find(&inner, f::FIRST_LEDGER_SEQUENCE)
                        .and_then(stobject::u32_of)
                        .ok_or_else(|| Error::Malformed("missing FirstLedgerSequence".into()))?,
                });
            }
        }
        Ok(NegativeUnl {
            disabled,
            to_disable: stobject::find(&fs, f::VALIDATOR_TO_DISABLE).map(<[u8]>::to_vec),
            to_re_enable: stobject::find(&fs, f::VALIDATOR_TO_RE_ENABLE).map(<[u8]>::to_vec),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(h: &str) -> NegativeUnl {
        NegativeUnl::parse(&hex::decode(h).unwrap()).unwrap()
    }

    // Real objects from mainnet history (s2.ripple.com, ledger_entry,
    // binary), flag ledgers from a sample taken 2026-10-24.

    #[test]
    fn one_disabled_validator() {
        // Ledger 68 999 936.
        let n = parse(
            "11004E2200000000F011E013201A041CDB007121EDA5AAE0DB134B809F8D664888F7EC4FCE98DC4D00B33301032424941C16C2F0F7E1F1",
        );
        assert_eq!(n.disabled.len(), 1);
        assert_eq!(n.disabled[0].since, 0x041C_DB00);
        assert_eq!(n.disabled[0].master_key[0], 0xED);
        assert_eq!(n.to_disable, None);
    }

    #[test]
    fn only_a_candidate_to_disable() {
        // Ledger 70 999 808: nobody disabled, one candidate.
        let n = parse(
            "11004E2200000000701421ED2C1468B4A11D281F93EF337C95E4A08DF0000FDEFB6D0EA9BC05FBD5D61A1F5A",
        );
        assert!(n.disabled.is_empty());
        assert_eq!(n.to_disable.unwrap().len(), 33);
    }

    #[test]
    fn disabled_and_candidate_to_re_enable() {
        // Ledger 102 999 808: the same validator is disabled and queued for re-enabling.
        let n = parse(
            "11004E2200000000250623A700554CA8ED5F00C7CCEA679D925E02397D5FCAEA6F12B24F996F990CB6D7488DBA36701521ED580C4282950CB3F7E0185F37F2CFB216882C5EDDD3BB1EE49C304A1AA3C5DB92F011E013201A0623A7007121ED580C4282950CB3F7E0185F37F2CFB216882C5EDDD3BB1EE49C304A1AA3C5DB92E1F1",
        );
        assert_eq!(n.disabled.len(), 1);
        assert_eq!(
            n.to_re_enable.as_deref(),
            Some(&n.disabled[0].master_key[..])
        );
    }

    #[test]
    fn two_disabled_validators() {
        // Ledger 105 999 872.
        let n = parse(
            "11004E22000000002506516E005560D246507BAD8B86574F5C59851CC8BECFD1AB1F3F15F90A7CC8D65EA87F24C5701521EDCF08053DFF0F00AC6E78B61F7B7FD187AF74052DEB5074207506D3A2CDCD9E5CF011E013201A065163007121EDCF08053DFF0F00AC6E78B61F7B7FD187AF74052DEB5074207506D3A2CDCD9E5CE1E013201A065169007121ED8252C2F91523126EEF9A21964C7E487A10D6D63D459139700DBC70D9F7BAD542E1F1",
        );
        assert_eq!(n.disabled.len(), 2);
        assert_ne!(n.disabled[0].master_key, n.disabled[1].master_key);
        assert_eq!(n.disabled[0].since, 0x0651_6300);
        assert_eq!(n.disabled[1].since, 0x0651_6900);
        // Flag ledgers are multiples of 256.
        assert!(n.disabled.iter().all(|d| d.since % 256 == 0));
    }

    #[test]
    fn other_entries_are_refused() {
        // A validation is not a NegativeUNL object.
        assert!(NegativeUnl::parse(&[0x22, 0, 0, 0, 1]).is_err());
    }
}
