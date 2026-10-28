//! One prepared physical block cache with actual ASIX2 query routing.
use super::*;
use sha2::{Digest, Sha512};
use std::io::{Read as _, Seek as _};
enum Data {
    Prepared(Box<fast::Prepared>),
    Rows(Vec<Row>),
}
struct Cached {
    index: usize,
    first: u32,
    data: Data,
}
pub struct Reader {
    archive: ArchiveFile,
    pub index: indexed::Indexes,
    cache: Option<Cached>,
    pub block_loads: usize,
}
impl Reader {
    pub fn open(
        archive: impl AsRef<std::path::Path>,
        index: impl AsRef<std::path::Path>,
    ) -> Res<Self> {
        Ok(Self {
            archive: ArchiveFile::open(archive)?,
            index: indexed::Indexes::decode(&std::fs::read(index).map_err(er)?)?,
            cache: None,
            block_loads: 0,
        })
    }
    pub fn clear_cache(&mut self) {
        self.cache = None;
    }
    fn prepare(&mut self, seq: u32) -> Res<&mut Cached> {
        let i = self
            .archive
            .entries
            .partition_point(|e| e.first <= seq)
            .checked_sub(1)
            .ok_or("ledger extent")?;
        let e = &self.archive.entries[i];
        if u64::from(seq) >= u64::from(e.first) + e.count as u64 {
            return Err("ledger extent".into());
        }
        if self.cache.as_ref().is_none_or(|c| c.index != i) {
            self.cache = None;
            self.archive
                .file
                .seek(std::io::SeekFrom::Start(e.offset))
                .map_err(er)?;
            let mut payload = vec![0; e.length];
            self.archive.file.read_exact(&mut payload).map_err(er)?;
            let mut p = Read::new(&payload);
            let data = match p.byte()? {
                1 => {
                    let mut f = fast::Prepared::for_read(&payload[1..])?;
                    if f.layout.len() != e.count {
                        return Err("block count".into());
                    }
                    let mut hash = Sha512::new();
                    hash.update((e.count as u32).to_le_bytes());
                    let mut previous: Option<LedgerHeader> = None;
                    for i in 0..e.count {
                        let row = f.row(i)?;
                        if row.seq != e.first.checked_add(i as u32).ok_or("sequence overflow")? {
                            return Err("block sequence".into());
                        }
                        verify(std::slice::from_ref(&row))?;
                        let h = LedgerHeader::parse(&row.header).map_err(er)?;
                        if previous.as_ref().is_some_and(|p| h.parent_hash != p.hash()) {
                            return Err("chain gap".into());
                        }
                        previous = Some(h);
                        // Same framing as rows_bytes, one ledger at a time.
                        let bytes = rows_bytes(std::slice::from_ref(&row));
                        hash.update(&bytes[4..]);
                    }
                    if hash.finalize()[..32] != e.hash {
                        return Err("block identity".into());
                    }
                    Data::Prepared(Box::new(f))
                }
                0 => {
                    let n = u64::from_le_bytes(p.take(8)?.try_into().unwrap());
                    if n > MAX as u64 {
                        return Err("raw limit".into());
                    }
                    let raw = zstd::bulk::decompress(&payload[p.p..], n as usize).map_err(er)?;
                    if raw.len() != n as usize {
                        return Err("raw size".into());
                    }
                    let rows = load_rows(&raw)?;
                    if rows.len() != e.count
                        || rows.first().is_none_or(|r| r.seq != e.first)
                        || sha512_half(&raw) != e.hash
                    {
                        return Err("block identity".into());
                    }
                    verify(&rows)?;
                    Data::Rows(rows)
                }
                _ => return Err("block mode".into()),
            };
            self.cache = Some(Cached {
                index: i,
                first: e.first,
                data,
            });
            self.block_loads += 1;
        }
        Ok(self.cache.as_mut().unwrap())
    }
    pub fn ledger(&mut self, seq: u32) -> Res<Row> {
        let c = self.prepare(seq)?;
        let local = (seq - c.first) as usize;
        match &mut c.data {
            Data::Prepared(f) => f.row(local),
            Data::Rows(rows) => rows.get(local).cloned().ok_or("ledger extent".into()),
        }
    }
    pub fn tx_storage(&mut self, storage: usize) -> Res<(Vec<u8>, Vec<u8>)> {
        let (seq, within) = self.index.storage_location(storage)?;
        let c = self.prepare(seq)?;
        let local = (seq - c.first) as usize;
        match &mut c.data {
            Data::Prepared(f) => {
                let base: usize = f.layout.iter().take(local).map(|r| r.tx.len()).sum();
                if f.layout.get(local).is_none_or(|r| within >= r.tx.len()) {
                    return Err("TX extent".into());
                }
                f.tx(base + within)
            }
            Data::Rows(rows) => rows
                .get(local)
                .and_then(|r| r.txs.get(within))
                .cloned()
                .ok_or("TX extent".into()),
        }
    }
    pub fn tx(&mut self, hash: &[u8; 32]) -> Res<Option<(Vec<u8>, Vec<u8>)>> {
        for n in self.index.tx_candidates(hash)? {
            let tx = self.tx_storage(n)?;
            if shamap::tx_id(&tx.0) == *hash {
                return Ok(Some(tx));
            }
        }
        Ok(None)
    }
    pub fn heap_bytes(&self) -> usize {
        self.index.memory_bytes()
            + self.cache.as_ref().map_or(0, |c| match &c.data {
                Data::Prepared(f) => f.memory_bytes(),
                Data::Rows(rows) => rows
                    .iter()
                    .map(|r| {
                        r.header.capacity()
                            + r.txs
                                .iter()
                                .map(|(t, m)| t.capacity() + m.capacity())
                                .sum::<usize>()
                            + r.patches
                                .iter()
                                .map(|(_, v)| v.capacity() + 32)
                                .sum::<usize>()
                    })
                    .sum(),
            })
    }
}
