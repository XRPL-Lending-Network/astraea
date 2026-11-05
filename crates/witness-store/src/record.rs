//! One archive record is one received validation.
//!
//! Record layout, all integers little-endian:
//!
//! ```text
//! u32  length of the rest of the record (12 + length of the original)
//! u64  time the archiver received it, ms since the Unix epoch
//! u32  ledger index, for navigation without parsing the original
//! ...  original: the raw signed validation (the stream's `data` field)
//! ```
//!
//! The leading length lets crash recovery tell a complete record from one
//! cut off halfway.

/// A validation whose original is this large is certainly garbage. Real ones
/// are about 233 bytes; with amendments and fees in the body, up to a couple
/// hundred bytes more.
pub const MAX_DATA_LEN: usize = 4096;

const FIXED_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub received_ms: u64,
    pub ledger_index: u32,
    /// The raw signed validation.
    pub data: Vec<u8>,
}

impl Record {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let body_len = u32::try_from(FIXED_LEN + self.data.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&body_len.to_le_bytes());
        out.extend_from_slice(&self.received_ms.to_le_bytes());
        out.extend_from_slice(&self.ledger_index.to_le_bytes());
        out.extend_from_slice(&self.data);
    }

    /// Parses the record at the start of `buf`.
    ///
    /// `Ok(None)` means there is not enough data for a whole record: either the
    /// normal end of the journal or a torn tail after a crash.
    pub fn decode(buf: &[u8]) -> Result<Option<(Record, usize)>, String> {
        let Some(len_bytes) = buf.get(..4) else {
            return Ok(None);
        };
        let body_len =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if !(FIXED_LEN..=FIXED_LEN + MAX_DATA_LEN).contains(&body_len) {
            return Err(format!("impossible record length {body_len}"));
        }
        let Some(body) = buf.get(4..4 + body_len) else {
            return Ok(None);
        };
        let mut ms = [0u8; 8];
        ms.copy_from_slice(&body[..8]);
        let mut li = [0u8; 4];
        li.copy_from_slice(&body[8..12]);
        Ok(Some((
            Record {
                received_ms: u64::from_le_bytes(ms),
                ledger_index: u32::from_le_bytes(li),
                data: body[FIXED_LEN..].to_vec(),
            },
            4 + body_len,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(i: u32) -> Record {
        Record {
            received_ms: 1_790_000_000_000 + u64::from(i),
            ledger_index: 107_000_000 + i,
            data: vec![0x22, 0x80, i as u8, 0x01],
        }
    }

    #[test]
    fn roundtrip() {
        let mut buf = Vec::new();
        for i in 0..3 {
            sample(i).encode_into(&mut buf);
        }
        let mut at = 0;
        for i in 0..3 {
            let (r, used) = Record::decode(&buf[at..]).unwrap().unwrap();
            assert_eq!(r, sample(i));
            at += used;
        }
        assert_eq!(at, buf.len());
        assert!(Record::decode(&buf[at..]).unwrap().is_none());
    }

    #[test]
    fn torn_tail_is_not_an_error() {
        let mut buf = Vec::new();
        sample(7).encode_into(&mut buf);
        for cut in 0..buf.len() {
            assert!(
                Record::decode(&buf[..cut]).unwrap().is_none(),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn garbage_length_is_rejected() {
        let buf = [0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0];
        assert!(Record::decode(&buf).is_err());
    }
}
