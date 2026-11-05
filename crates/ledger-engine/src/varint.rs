//! Variable-length integers in the cold store's tables.

pub(crate) fn put(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub(crate) fn get(b: &[u8], at: &mut usize) -> Result<u64, &'static str> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let x = *b.get(*at).ok_or("varint truncated")?;
        *at += 1;
        v |= u64::from(x & 0x7F) << shift;
        if x & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err("varint too long")
}
