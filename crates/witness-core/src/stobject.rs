//! Splitting a serialized XRPL object (STObject) into fields.
//!
//! Each field is a header (type code and field code) and a value. The parser
//! does not rebuild the object; it returns slices of the original bytes:
//! checking a signature needs exactly the bytes the validator signed, not our
//! copy of them.
//!
//! All types found in validations, manifests, transactions, metadata and
//! state objects are supported: fixed and variable length, amounts, nested
//! objects and arrays, paths, Issue, the XChain bridge. An unknown type is an
//! error: silently skipping what we don't understand is not allowed.

use std::fmt;

/// XRPL field type codes.
pub mod types {
    pub const UINT16: u16 = 1;
    pub const UINT32: u16 = 2;
    pub const UINT64: u16 = 3;
    pub const HASH128: u16 = 4;
    pub const HASH256: u16 = 5;
    pub const AMOUNT: u16 = 6;
    pub const BLOB: u16 = 7;
    pub const ACCOUNT: u16 = 8;
    /// Floating-point number: i64 mantissa and i32 exponent.
    pub const NUMBER: u16 = 9;
    pub const INT32: u16 = 10;
    pub const INT64: u16 = 11;
    pub const OBJECT: u16 = 14;
    pub const ARRAY: u16 = 15;
    pub const UINT8: u16 = 16;
    pub const HASH160: u16 = 17;
    pub const PATHSET: u16 = 18;
    pub const VECTOR256: u16 = 19;
    pub const UINT96: u16 = 20;
    pub const HASH192: u16 = 21;
    pub const UINT384: u16 = 22;
    pub const UINT512: u16 = 23;
    pub const ISSUE: u16 = 24;
    pub const XCHAIN_BRIDGE: u16 = 25;
    pub const CURRENCY: u16 = 26;
}

/// A field by its (type, code) pair, as in the xrpld field definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldId {
    pub type_code: u16,
    pub field_code: u16,
}

impl FieldId {
    pub const fn new(type_code: u16, field_code: u16) -> FieldId {
        FieldId {
            type_code,
            field_code,
        }
    }
}

/// Fields found in validations and manifests.
pub mod fields {
    use super::{FieldId, types::*};

    pub const VERSION: FieldId = FieldId::new(UINT16, 16);
    pub const FLAGS: FieldId = FieldId::new(UINT32, 2);
    pub const SEQUENCE: FieldId = FieldId::new(UINT32, 4);
    pub const LEDGER_SEQUENCE: FieldId = FieldId::new(UINT32, 6);
    pub const CLOSE_TIME: FieldId = FieldId::new(UINT32, 7);
    pub const SIGNING_TIME: FieldId = FieldId::new(UINT32, 9);
    pub const LOAD_FEE: FieldId = FieldId::new(UINT32, 24);
    pub const RESERVE_BASE: FieldId = FieldId::new(UINT32, 31);
    pub const RESERVE_INCREMENT: FieldId = FieldId::new(UINT32, 32);
    pub const BASE_FEE: FieldId = FieldId::new(UINT64, 5);
    pub const COOKIE: FieldId = FieldId::new(UINT64, 10);
    pub const SERVER_VERSION: FieldId = FieldId::new(UINT64, 11);
    pub const LEDGER_HASH: FieldId = FieldId::new(HASH256, 1);
    pub const CONSENSUS_HASH: FieldId = FieldId::new(HASH256, 23);
    pub const VALIDATED_HASH: FieldId = FieldId::new(HASH256, 25);
    pub const PUBLIC_KEY: FieldId = FieldId::new(BLOB, 1);
    pub const SIGNING_PUB_KEY: FieldId = FieldId::new(BLOB, 3);
    pub const SIGNATURE: FieldId = FieldId::new(BLOB, 6);
    pub const DOMAIN: FieldId = FieldId::new(BLOB, 7);
    pub const MASTER_SIGNATURE: FieldId = FieldId::new(BLOB, 18);
    pub const AMENDMENTS: FieldId = FieldId::new(VECTOR256, 3);
    pub const LEDGER_ENTRY_TYPE: FieldId = FieldId::new(UINT16, 1);
    pub const FIRST_LEDGER_SEQUENCE: FieldId = FieldId::new(UINT32, 26);
    pub const VALIDATOR_TO_DISABLE: FieldId = FieldId::new(BLOB, 20);
    pub const VALIDATOR_TO_RE_ENABLE: FieldId = FieldId::new(BLOB, 21);
    pub const DISABLED_VALIDATORS: FieldId = FieldId::new(ARRAY, 17);
    pub const DISABLED_VALIDATOR: FieldId = FieldId::new(OBJECT, 19);
}

/// End of a nested object (type 14, field 1) and of an array (type 15, field 1).
pub const OBJECT_END: u8 = 0xE1;
pub const ARRAY_END: u8 = 0xF1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The data ended in the middle of a field.
    Truncated { at: usize },
    /// A type we do not parse.
    UnsupportedType { at: usize, type_code: u16 },
    /// Invalid length or value.
    Malformed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { at } => write!(f, "data truncated at offset {at}"),
            Error::UnsupportedType { at, type_code } => {
                write!(f, "field type {type_code} at offset {at} is not supported")
            }
            Error::Malformed(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

/// An object field: header and value as slices of the original bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    pub id: FieldId,
    /// The value without its length prefix.
    pub value: &'a [u8],
    /// The whole field: header, length prefix, value.
    pub raw: &'a [u8],
}

fn take(buf: &[u8], at: usize, n: usize) -> Result<&[u8], Error> {
    buf.get(at..at + n).ok_or(Error::Truncated { at })
}

/// Length of a variable-length (VL) value: a 1 to 3 byte prefix.
fn read_vl(buf: &[u8], at: usize) -> Result<(usize, usize), Error> {
    let b1 = usize::from(*buf.get(at).ok_or(Error::Truncated { at })?);
    match b1 {
        0..=192 => Ok((b1, 1)),
        193..=240 => {
            let b2 = usize::from(*buf.get(at + 1).ok_or(Error::Truncated { at })?);
            Ok((193 + (b1 - 193) * 256 + b2, 2))
        }
        241..=254 => {
            let b = take(buf, at + 1, 2)?;
            Ok((
                12_481 + (b1 - 241) * 65_536 + usize::from(b[0]) * 256 + usize::from(b[1]),
                3,
            ))
        }
        _ => Err(Error::Malformed(format!(
            "invalid length prefix {b1} at offset {at}"
        ))),
    }
}

fn fixed_len(type_code: u16) -> Option<usize> {
    use types::*;
    Some(match type_code {
        UINT8 => 1,
        UINT16 => 2,
        UINT32 | INT32 => 4,
        UINT64 | INT64 => 8,
        NUMBER => 12,
        CURRENCY => 20,
        UINT96 => 12,
        HASH128 => 16,
        HASH160 => 20,
        HASH192 => 24,
        HASH256 => 32,
        UINT384 => 48,
        UINT512 => 64,
        _ => return None,
    })
}

/// Length of an Issue: 20 zero bytes is XRP; otherwise currency and issuer,
/// and for MPT the issuer in place of the currency, then the special
/// "no account" value and the issuance sequence.
fn issue_len(buf: &[u8], at: usize) -> Result<usize, Error> {
    let first = take(buf, at, 20)?;
    if first.iter().all(|b| *b == 0) {
        return Ok(20);
    }
    let second = take(buf, at + 20, 20)?;
    let no_account = second[..19].iter().all(|b| *b == 0) && second[19] == 1;
    Ok(if no_account { 44 } else { 40 })
}

/// Length of a path set: steps with flags (account, currency, issuer, 20 bytes
/// each), 0xFF is a path boundary, 0x00 is the end.
fn pathset_len(buf: &[u8], start: usize) -> Result<usize, Error> {
    let mut at = start;
    loop {
        let t = *buf.get(at).ok_or(Error::Truncated { at })?;
        at += 1;
        match t {
            0x00 => return Ok(at - start),
            0xFF => {}
            _ if t & !0x31 != 0 => {
                return Err(Error::Malformed(format!(
                    "unknown path step {t:#04x} at offset {}",
                    at - 1
                )));
            }
            _ => at += 20 * (t & 0x31).count_ones() as usize,
        }
    }
}

/// Splits an object into fields in their original order.
pub fn fields(buf: &[u8]) -> Result<Vec<Field<'_>>, Error> {
    let (out, _) = sequence(buf, 0, None, 0, false)?;
    Ok(out)
}

/// Array elements from the array's value: every element is an object, whatever
/// field names it (as in XRPLA's `wire.cpp` and STArray in xrpld). An
/// element's value is its fields without the end marker.
pub fn items(buf: &[u8]) -> Result<Vec<Field<'_>>, Error> {
    let (out, _) = sequence(buf, 0, None, 0, true)?;
    Ok(out)
}

/// Nesting depth limit for objects and arrays. xrpld uses 10 (`STVar`); this
/// one leaves headroom but is still finite: the parser is recursive, and
/// network input with thousands of nesting levels would otherwise overflow the stack.
pub const MAX_DEPTH: usize = 32;

/// Fields of a nested object or elements of an array, from the field's value.
pub fn children<'a>(f: &Field<'a>) -> Result<Vec<Field<'a>>, Error> {
    if f.id.type_code == types::ARRAY {
        items(f.value)
    } else {
        fields(f.value)
    }
}

/// The field header at `at`: type, field code and the offset right after the header.
pub fn head(buf: &[u8], mut at: usize) -> Result<(u16, u16, usize), Error> {
    let b = *buf.get(at).ok_or(Error::Truncated { at })?;
    let (mut type_code, mut field_code) = (u16::from(b >> 4), u16::from(b & 0x0F));
    at += 1;
    if type_code == 0 {
        type_code = u16::from(*buf.get(at).ok_or(Error::Truncated { at })?);
        at += 1;
    }
    if field_code == 0 {
        field_code = u16::from(*buf.get(at).ok_or(Error::Truncated { at })?);
        at += 1;
    }
    Ok((type_code, field_code, at))
}

/// Where the value of a field of type `type_code` is, if the header ended at `at`:
/// (value start, length). `None` for an object or array: their value runs
/// up to the end marker.
pub fn extent(buf: &[u8], at: usize, type_code: u16) -> Result<Option<(usize, usize)>, Error> {
    if let Some(n) = fixed_len(type_code) {
        return Ok(Some((at, n)));
    }
    Ok(Some(match type_code {
        types::BLOB | types::ACCOUNT | types::VECTOR256 => {
            let (n, used) = read_vl(buf, at)?;
            (at + used, n)
        }
        types::ISSUE => (at, issue_len(buf, at)?),
        types::PATHSET => (at, pathset_len(buf, at)?),
        types::XCHAIN_BRIDGE => {
            // Door (length-prefixed account), Issue, door, Issue.
            let mut n = 0;
            for _ in 0..2 {
                let (len, used) = read_vl(buf, at + n)?;
                n += used + len;
                n += issue_len(buf, at + n)?;
            }
            (at, n)
        }
        types::AMOUNT => {
            let first = *buf.get(at).ok_or(Error::Truncated { at })?;
            // The top bit means an issued currency (48 bytes). MPT (33 bytes)
            // only when the first byte is flags alone, 0x60 or 0x20: in XRP
            // amounts from 2013 the 0x20 bit can be part of the value (as in
            // XRPLA's wire.cpp). Otherwise XRP in drops.
            let n = if first & 0x80 != 0 {
                48
            } else if first == 0x60 || first == 0x20 {
                33
            } else {
                8
            };
            (at, n)
        }
        _ => return Ok(None),
    }))
}

/// Fields from `at` up to the end marker `stop` (not including it) or to the end of the buffer.
/// Returns the fields and the offset right after the marker.
fn sequence(
    buf: &[u8],
    mut at: usize,
    stop: Option<u8>,
    depth: usize,
    in_array: bool,
) -> Result<(Vec<Field<'_>>, usize), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::Malformed(format!(
            "nesting deeper than {MAX_DEPTH} at offset {at}"
        )));
    }
    let mut out = Vec::new();
    loop {
        if at >= buf.len() {
            return match stop {
                None => Ok((out, at)),
                Some(_) => Err(Error::Truncated { at }),
            };
        }
        if let Some(m) = stop
            && buf[at] == m
        {
            return Ok((out, at + 1));
        }
        if buf[at] == OBJECT_END || buf[at] == ARRAY_END {
            return Err(Error::Malformed(format!("stray end marker at offset {at}")));
        }
        let start = at;
        let (type_code, field_code, after_head) = head(buf, at)?;
        at = after_head;
        if in_array {
            let (_, after) = sequence(buf, at, Some(OBJECT_END), depth + 1, false)?;
            out.push(Field {
                id: FieldId::new(type_code, field_code),
                value: &buf[at..after - 1],
                raw: &buf[start..after],
            });
            at = after;
            continue;
        }
        let (value_at, len) = match extent(buf, at, type_code)? {
            Some(x) => x,
            None => match type_code {
                types::OBJECT | types::ARRAY => {
                    let marker = if type_code == types::OBJECT {
                        OBJECT_END
                    } else {
                        ARRAY_END
                    };
                    let (_, after) =
                        sequence(buf, at, Some(marker), depth + 1, type_code == types::ARRAY)?;
                    // The value excludes the end marker; the whole field includes it.
                    out.push(Field {
                        id: FieldId::new(type_code, field_code),
                        value: &buf[at..after - 1],
                        raw: &buf[start..after],
                    });
                    at = after;
                    continue;
                }
                _ => {
                    return Err(Error::UnsupportedType {
                        at: start,
                        type_code,
                    });
                }
            },
        };
        let value = take(buf, value_at, len)?;
        at = value_at + len;
        out.push(Field {
            id: FieldId::new(type_code, field_code),
            value,
            raw: &buf[start..at],
        });
    }
}

/// Object bytes for signing: all fields except signatures, in their original order.
pub fn signing_bytes(fields: &[Field<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        if f.id != self::fields::SIGNATURE && f.id != self::fields::MASTER_SIGNATURE {
            out.extend_from_slice(f.raw);
        }
    }
    out
}

pub fn find<'a>(fields: &[Field<'a>], id: FieldId) -> Option<&'a [u8]> {
    fields.iter().find(|f| f.id == id).map(|f| f.value)
}

pub fn u32_of(v: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(v.try_into().ok()?))
}

pub fn u64_of(v: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(v.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_paths_and_numbers() {
        // Issue (type 24, field 3): XRP, then a currency with an issuer.
        let mut buf = vec![0x03, 0x18];
        buf.extend([0u8; 20]);
        buf.extend([0x03, 0x18]);
        buf.extend([7u8; 40]);
        // MPT: issuer, "no account", issuance sequence.
        buf.extend([0x03, 0x18]);
        buf.extend([7u8; 20]);
        buf.extend([0u8; 19]);
        buf.extend([1u8, 0, 0, 0, 5]);
        // Number (type 9, field 1): 12 bytes.
        buf.extend([0x91]);
        buf.extend([1u8; 12]);
        // Paths (type 18, field 1): a step with an account, a boundary, a step
        // with a currency and issuer, the end.
        buf.extend([0x01, 0x12, 0x01]);
        buf.extend([2u8; 20]);
        buf.push(0xFF);
        buf.push(0x30);
        buf.extend([3u8; 40]);
        buf.push(0x00);
        let f = fields(&buf).unwrap();
        let lens: Vec<_> = f.iter().map(|f| f.value.len()).collect();
        assert_eq!(lens, vec![20, 40, 44, 12, 64]);
        assert!(fields(&[0x01, 0x12, 0x02]).is_err(), "unknown path step");
    }

    #[test]
    fn length_prefixes() {
        assert_eq!(read_vl(&[0], 0).unwrap(), (0, 1));
        assert_eq!(read_vl(&[192], 0).unwrap(), (192, 1));
        assert_eq!(read_vl(&[193, 0], 0).unwrap(), (193, 2));
        assert_eq!(read_vl(&[240, 255], 0).unwrap(), (12_480, 2));
        assert_eq!(read_vl(&[241, 0, 0], 0).unwrap(), (12_481, 3));
        assert!(read_vl(&[255], 0).is_err());
        assert!(read_vl(&[200], 0).is_err());
    }

    #[test]
    fn headers_with_large_codes() {
        // MasterSignature: type 7, field 18, the field code is in the second byte.
        let buf = [0x70, 0x12, 0x02, 0xAA, 0xBB];
        let f = fields(&buf).unwrap();
        assert_eq!(f[0].id, self::fields::MASTER_SIGNATURE);
        assert_eq!(f[0].value, &[0xAA, 0xBB]);
        // Vector256 Amendments: type 19, the type code is in the second byte.
        let buf = [0x03, 0x13, 0x00];
        assert_eq!(fields(&buf).unwrap()[0].id, self::fields::AMENDMENTS);
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_crash() {
        // 20 000 nested objects, 40 000 bytes.
        let mut buf = vec![0xE2; 20_000];
        buf.extend(vec![0xE1; 20_000]);
        assert!(matches!(fields(&buf), Err(Error::Malformed(_))));
        // Normal nesting parses.
        let mut ok = vec![0xE2; 8];
        ok.extend(vec![0xE1; 8]);
        assert!(fields(&ok).is_ok());
    }

    #[test]
    fn truncation_and_stray_markers_are_errors() {
        assert!(matches!(
            fields(&[0x22, 0x80]),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(fields(&[0xE1]), Err(Error::Malformed(_))));
        // An array without an end marker.
        assert!(matches!(
            fields(&[0xF0, 0x11, 0xE0, 0x13, 0xE1]),
            Err(Error::Truncated { .. })
        ));
        // XRPL has no type 12.
        assert!(matches!(
            fields(&[0xC1, 0x00]),
            Err(Error::UnsupportedType { type_code: 12, .. })
        ));
    }
}
