//! Reversible field-column transform inside one independently compressed program capsule.
use super::{MAX, Read, Res, Shape, put};
use std::collections::BTreeMap;
type Columns = BTreeMap<(usize, usize), Vec<u64>>;
fn collect(
    r: &mut Read<'_>,
    shapes: &[Vec<Shape>],
    order: &mut Vec<usize>,
    cols: &mut Columns,
    depth: usize,
) -> Res<()> {
    if depth > 64 {
        return Err("column tree depth".into());
    }
    let id = r.count()?;
    order.push(id);
    let shape = shapes.get(id).ok_or("column template")?;
    let mut slot = 0;
    for step in shape {
        match step {
            Shape::Fixed(_) => {}
            Shape::Value => {
                cols.entry((id, slot)).or_default().push(r.var()?);
                slot += 1;
            }
            Shape::Child => collect(r, shapes, order, cols, depth + 1)?,
        }
    }
    Ok(())
}
pub(super) fn encode(raw: &[u8], shapes: &[Vec<Shape>]) -> Res<Vec<u8>> {
    let mut r = Read::new(raw);
    let docs = r.count()?;
    let mut order = vec![];
    let mut cols = Columns::new();
    for _ in 0..docs {
        let n = r.count()?;
        let start = r.p;
        for _ in 0..n {
            r.var()?;
        }
        let mut p = Read::new(&raw[start..r.p]);
        collect(&mut p, shapes, &mut order, &mut cols, 0)?;
        p.end()?;
    }
    r.end()?;
    let mut out = vec![];
    put(&mut out, docs as u64);
    put(&mut out, order.len() as u64);
    for id in order {
        put(&mut out, id as u64);
    }
    put(&mut out, cols.len() as u64);
    for ((id, slot), values) in cols {
        put(&mut out, id as u64);
        put(&mut out, slot as u64);
        put(&mut out, values.len() as u64);
        let mut plain = vec![];
        let mut delta = vec![];
        let mut prev = 0u64;
        for x in values {
            put(&mut plain, x);
            let d = x.wrapping_sub(prev) as i64;
            put(&mut delta, ((d << 1) ^ (d >> 63)) as u64);
            prev = x;
        }
        if delta.len() < plain.len() {
            out.push(1);
            out.extend(delta);
        } else {
            out.push(0);
            out.extend(plain);
        }
    }
    Ok(out)
}
fn restore(
    order: &[usize],
    at: &mut usize,
    shapes: &[Vec<Shape>],
    cols: &mut BTreeMap<(usize, usize), (usize, Vec<u64>)>,
    ops: &mut Vec<u64>,
    depth: usize,
) -> Res<()> {
    if depth > 64 {
        return Err("column tree depth".into());
    }
    let id = *order.get(*at).ok_or("column node order")?;
    *at += 1;
    ops.push(id as u64);
    let mut slot = 0;
    for step in shapes.get(id).ok_or("column template")? {
        match step {
            Shape::Fixed(_) => {}
            Shape::Value => {
                let (cursor, v) = cols.get_mut(&(id, slot)).ok_or("missing column")?;
                ops.push(*v.get(*cursor).ok_or("exhausted column")?);
                *cursor += 1;
                slot += 1;
            }
            Shape::Child => restore(order, at, shapes, cols, ops, depth + 1)?,
        }
        if ops.len() > MAX / 8 {
            return Err("column expansion limit".into());
        }
    }
    Ok(())
}
pub(super) fn decode(raw: &[u8], shapes: &[Vec<Shape>]) -> Res<Vec<u8>> {
    let mut r = Read::new(raw);
    let docs = r.count()?;
    let mut order = vec![];
    for _ in 0..r.count()? {
        order.push(r.count()?);
    }
    let mut cols = BTreeMap::new();
    for _ in 0..r.count()? {
        let id = r.count()?;
        let slot = r.count()?;
        let n = r.count()?;
        let mode = r.byte()?;
        if mode > 1 {
            return Err("column coding mode".into());
        }
        let mut values = vec![];
        let mut prev = 0u64;
        for _ in 0..n {
            let x = r.var()?;
            prev = if mode == 1 {
                prev.wrapping_add((((x >> 1) as i64) ^ -((x & 1) as i64)) as u64)
            } else {
                x
            };
            values.push(prev);
        }
        if cols.insert((id, slot), (0, values)).is_some() {
            return Err("duplicate column".into());
        }
    }
    r.end()?;
    let mut out = vec![];
    put(&mut out, docs as u64);
    let mut at = 0;
    for _ in 0..docs {
        let mut ops = vec![];
        restore(&order, &mut at, shapes, &mut cols, &mut ops, 0)?;
        put(&mut out, ops.len() as u64);
        for x in ops {
            put(&mut out, x);
        }
        if out.len() > MAX {
            return Err("program expansion limit".into());
        }
    }
    if at != order.len() || cols.values().any(|(i, v)| *i != v.len()) {
        return Err("unused column data".into());
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn columns_roundtrip_nested_and_wrapping_tokens() {
        let shapes = vec![
            vec![Shape::Value, Shape::Child],
            vec![Shape::Fixed(vec![0]), Shape::Value],
        ];
        let mut raw = vec![];
        put(&mut raw, 4);
        for v in [0, u64::MAX, 1, 1234] {
            put(&mut raw, 4);
            put(&mut raw, 0);
            put(&mut raw, v);
            put(&mut raw, 1);
            put(&mut raw, 17);
        }
        let back = encode(&raw, &shapes).unwrap();
        assert_eq!(decode(&back, &shapes).unwrap(), raw);
        assert!(decode(&back[..back.len() - 1], &shapes).is_err());
    }
}
