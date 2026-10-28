//! A validation is a statement signed by a validator: "ledger N has hash H".
//!
//! The signature covers the `VAL\0` prefix and every field except the
//! signature itself. Checking the signature proves one thing: this key signed
//! this statement. That the key belongs to a particular validator is what the
//! manifest says; that the network confirmed the ledger is a quorum under a
//! trust policy. These are different claims and must not be mixed here.

use crate::keys::{VerifyError, verify};
use crate::stobject::{self, Error, fields as f};
use crate::{HashPrefix, sha512_half};

/// Full validation: the validator considers this ledger accepted.
pub const FLAG_FULL: u32 = 0x0000_0001;
/// The secp256k1 signature must be canonical (low S).
pub const FLAG_FULLY_CANONICAL: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    pub flags: u32,
    pub ledger_sequence: u32,
    /// Signing time, seconds since the XRPL epoch (2000-01-01).
    pub signing_time: u32,
    pub ledger_hash: [u8; 32],
    pub consensus_hash: Option<[u8; 32]>,
    pub validated_hash: Option<[u8; 32]>,
    pub cookie: Option<u64>,
    pub server_version: Option<u64>,
    /// Amendments the validator votes for (only in flag ledgers).
    pub amendments: Vec<[u8; 32]>,
    pub signing_pub_key: Vec<u8>,
    pub signature: Vec<u8>,
    /// Exactly what is signed: the prefix and the fields without the signature.
    signing_data: Vec<u8>,
}

fn hash32(v: &[u8]) -> Result<[u8; 32], Error> {
    v.try_into()
        .map_err(|_| Error::Malformed("hash is not 32 bytes".into()))
}

fn required<'a>(
    fs: &[stobject::Field<'a>],
    id: stobject::FieldId,
    name: &str,
) -> Result<&'a [u8], Error> {
    stobject::find(fs, id).ok_or_else(|| Error::Malformed(format!("missing field {name}")))
}

impl Validation {
    pub fn parse(raw: &[u8]) -> Result<Validation, Error> {
        let fs = stobject::fields(raw)?;
        let u32_req = |id, name: &str| -> Result<u32, Error> {
            stobject::u32_of(required(&fs, id, name)?)
                .ok_or_else(|| Error::Malformed(format!("{name} is not 4 bytes")))
        };
        let amendments = match stobject::find(&fs, f::AMENDMENTS) {
            None => Vec::new(),
            Some(v) if v.len() % 32 == 0 => v.as_chunks::<32>().0.to_vec(),
            Some(_) => {
                return Err(Error::Malformed(
                    "Amendments is not a multiple of 32".into(),
                ));
            }
        };
        let mut signing_data = HashPrefix::Validation.to_bytes().to_vec();
        signing_data.extend(stobject::signing_bytes(&fs));
        Ok(Validation {
            flags: u32_req(f::FLAGS, "Flags")?,
            ledger_sequence: u32_req(f::LEDGER_SEQUENCE, "LedgerSequence")?,
            signing_time: u32_req(f::SIGNING_TIME, "SigningTime")?,
            ledger_hash: hash32(required(&fs, f::LEDGER_HASH, "LedgerHash")?)?,
            consensus_hash: stobject::find(&fs, f::CONSENSUS_HASH)
                .map(hash32)
                .transpose()?,
            validated_hash: stobject::find(&fs, f::VALIDATED_HASH)
                .map(hash32)
                .transpose()?,
            cookie: stobject::find(&fs, f::COOKIE).and_then(stobject::u64_of),
            server_version: stobject::find(&fs, f::SERVER_VERSION).and_then(stobject::u64_of),
            amendments,
            signing_pub_key: required(&fs, f::SIGNING_PUB_KEY, "SigningPubKey")?.to_vec(),
            signature: required(&fs, f::SIGNATURE, "Signature")?.to_vec(),
            signing_data,
        })
    }

    pub fn is_full(&self) -> bool {
        self.flags & FLAG_FULL != 0
    }

    /// The signature matches the signing key from the validation itself.
    pub fn verify(&self) -> Result<(), VerifyError> {
        verify(
            &self.signing_pub_key,
            &self.signing_data,
            &self.signature,
            self.flags & FLAG_FULLY_CANONICAL != 0,
        )
    }

    /// The hash of the signed data is a stable identifier of the statement: two
    /// validations with the same hash say the same thing, even if the signatures differ.
    pub fn signing_hash(&self) -> [u8; 32] {
        sha512_half(&self.signing_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::node_public;

    /// Live validations from an archive, 2026-10-23: two from mainnet
    /// (ledger 107846611) and one from testnet, relayed by peers.
    const MAINNET_A: &str = "228000000126066D9BD329326DE6C13A0393278390661EE1517C636107510AFFB3DFDD322187331C35D8071589D3CA451D39F13991D276159C501734B0E4E7762FA70177CDF225EF358D84A6C48805DB80A5531B6B52C2530A9F3B501985F573AEA90B3469CDE60E58202164B0B48CD74985EE0879E39F4DE55D841AA973210371ED125A7B4EA88D33EB92A12783D27A287FD7FEB95294C9183044624DC0D0A2764630440220798C71D5FE0C70BF0BE9C960854619A0DD3486D6D9462AD06DD8D7C70592456A02207808AFFBC83B6634EF22D2366F20B48363DE2468B73D1404A9ABEC0F72D0A19C";
    const MAINNET_B: &str = "220000000126066D9BD329326DE6C23A6AD9FE5EF53AE707517C636107510AFFB3DFDD322187331C35D8071589D3CA451D39F13991D276159C50197C636107510AFFB3DFDD322187331C35D8071589D3CA451D39F13991D276159C73210225BBFD07C6083A30470140ED89D850E145FA93517E9002B2EA254E1A8AAE67997646304402200E641559263D3A580A2727A04F48D488493AE75876B1C81F449C93AEECB1914302203DF88E856A9051C00CD9764C59ECF5776E174D9C78937A940E27B1B8776A8340";
    const TESTNET: &str = "228000000126014BFCE429326DE6C23A0221BB1AF1BE4BFD51694407F6CC5CCE9420EFD697A3B615158EE30D35AD8FA53F42DE61AF207CCB7F5017EA4EF6159D49CA382FF252D5232A59D979A61661B92BE15F6AEE5189305A4EEE5019062589656583C340F7B3255484884B8FE30524E9C0E3CC968A40C26C5AD8A23373210366985A2A58FCDD64004A0A1B0FE5C7550891436775AD50562DA6DFACE13AE62F7646304402207E50BDFD6B546DF7071E4E2DDCA21587FCF47CC01C66BC645371F684E307E0D802207713AF0411219528AF5E63F0F2ABED589F8E3265D0FDDB7B44CAB707B98712E7";

    fn parse(h: &str) -> Validation {
        Validation::parse(&hex::decode(h).unwrap()).unwrap()
    }

    #[test]
    fn live_validations_parse_and_verify() {
        let a = parse(MAINNET_A);
        assert_eq!(a.ledger_sequence, 107_846_611);
        assert!(a.is_full());
        assert!(a.consensus_hash.is_some() && a.validated_hash.is_some());
        assert!(node_public(&a.signing_pub_key).starts_with('n'));
        a.verify().unwrap();

        let b = parse(MAINNET_B);
        assert_eq!(b.ledger_sequence, 107_846_611);
        assert_eq!(b.ledger_hash, a.ledger_hash, "both signed the same ledger");
        b.verify().unwrap();

        let t = parse(TESTNET);
        assert_eq!(t.ledger_sequence, 21_757_156);
        t.verify().unwrap();
    }

    #[test]
    fn any_changed_byte_breaks_the_signature() {
        let raw = hex::decode(MAINNET_A).unwrap();
        // Ledger sequence: 4 bytes after the 0x26 header at offset 5.
        let mut forged = raw.clone();
        forged[9] ^= 1;
        let v = Validation::parse(&forged).unwrap();
        assert_eq!(v.ledger_sequence, 107_846_611 ^ 1);
        assert_eq!(v.verify(), Err(VerifyError::Mismatch));
        // Tampered ledger hash.
        let mut forged = raw;
        forged[30] ^= 0x80;
        assert_eq!(
            Validation::parse(&forged).unwrap().verify(),
            Err(VerifyError::Mismatch)
        );
    }

    #[test]
    fn missing_fields_are_errors() {
        // Flags only.
        assert!(Validation::parse(&[0x22, 0x80, 0, 0, 1]).is_err());
    }
}
