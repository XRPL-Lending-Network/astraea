//! JC04: joint scalar selection and separated instruction/argument streams.
use super::*;

pub(crate) enum Scalar {
    Literal(Vec<u8>),
    Dictionary(usize),
    Repeat,
    ContextDelta(u8, u64),
}
fn zig(d: i64) -> u64 {
    ((d as u64) << 1) ^ ((d >> 63) as u64)
}
fn unzig(z: u64) -> i64 {
    ((z >> 1) as i64) ^ -((z & 1) as i64)
}
fn var(n: u64) -> Vec<u8> {
    let mut v = vec![];
    put(&mut v, n);
    v
}
fn touch(recent: &mut Vec<usize>, id: usize) {
    if let Some(p) = recent.iter().position(|&x| x == id) {
        recent.remove(p);
    }
    recent.insert(0, id);
    recent.truncate(16);
}
pub(crate) fn encode(
    values: &[Option<Vec<u8>>],
    deltas: &[Option<(u8, u64)>],
    ids: &HashMap<Vec<u8>, usize>,
    compact_signatures: bool,
) -> Res<Vec<u8>> {
    encode_recent(values, deltas, ids, compact_signatures, false)
}
pub(crate) fn encode_recent(
    values: &[Option<Vec<u8>>],
    deltas: &[Option<(u8, u64)>],
    ids: &HashMap<Vec<u8>, usize>,
    compact_signatures: bool,
    mtf: bool,
) -> Res<Vec<u8>> {
    if values.len() != deltas.len() {
        return Err("joint delta count".into());
    }
    let (mut tags, mut args) = (vec![], vec![]);
    let (mut last_id, mut previous) = (0u64, [0u64; 2]);
    let mut recent = vec![];
    for (value, delta) in values.iter().zip(deltas) {
        let Some(v) = value else {
            tags.push(1);
            continue;
        };
        if [4, 8].contains(&v.len()) {
            let width = v.len();
            let slot = usize::from(width == 8);
            let mut bytes = [0u8; 8];
            bytes[8 - width..].copy_from_slice(v);
            let n = u64::from_be_bytes(bytes);
            let global = var(zig(n.wrapping_sub(previous[slot]) as i64));
            let context = delta
                .filter(|(w, _)| *w as usize == width)
                .map(|(_, z)| var(z));
            if let Some(d) = context.filter(|d| d.len() <= global.len() && d.len() < width) {
                tags.push(if width == 4 { 2 } else { 3 });
                args.extend(d);
            } else if global.len() < width {
                tags.push(if width == 4 { 5 } else { 6 });
                args.extend(global);
                previous[slot] = n;
            } else {
                tags.push(if width == 4 { 7 } else { 8 });
                args.extend(v);
                previous[slot] = n;
            }
        } else if let Some(&id) = ids.get(v) {
            if let Some(pos) = recent.iter().position(|&x| x == id).filter(|_| mtf) {
                tags.push(9);
                args.push(pos as u8);
            } else {
                tags.push(4);
                put(&mut args, zig((id as u64).wrapping_sub(last_id) as i64));
            }
            last_id = id as u64;
            touch(&mut recent, id);
        } else {
            tags.push(0);
            value_put(&mut args, v, compact_signatures);
        }
    }
    let mut out = vec![];
    blob(&mut out, &tags);
    blob(&mut out, &args);
    Ok(out)
}
#[cfg(test)]
fn decode(data: &[u8], count: usize, dictionary_len: usize) -> Res<Vec<Scalar>> {
    let mut out = vec![];
    decode_into(data, count, dictionary_len, |s| {
        out.push(s);
        Ok(())
    })?;
    Ok(out)
}
pub(crate) fn decode_into(
    data: &[u8],
    count: usize,
    dictionary_len: usize,
    mut emit: impl FnMut(Scalar) -> Res<()>,
) -> Res<()> {
    let mut r = Read::new(data);
    let tags = r.blob()?;
    let mut args = Read::new(r.blob()?);
    r.end()?;
    if tags.len() != count {
        return Err("joint tag count".into());
    }
    let (mut last_id, mut previous) = (0u64, [0u64; 2]);
    let mut recent = vec![];
    for &tag in tags {
        emit(match tag {
            0 => Scalar::Literal(value_get(&mut args)?),
            1 => Scalar::Repeat,
            2 | 3 => Scalar::ContextDelta(if tag == 2 { 4 } else { 8 }, args.var()?),
            4 => {
                last_id = last_id.wrapping_add(unzig(args.var()?) as u64);
                let id = usize::try_from(last_id).map_err(er)?;
                if id >= dictionary_len {
                    return Err("joint dictionary id".into());
                }
                touch(&mut recent, id);
                Scalar::Dictionary(id)
            }
            9 => {
                let id = *recent
                    .get(args.byte()? as usize)
                    .ok_or("joint recent index")?;
                touch(&mut recent, id);
                last_id = id as u64;
                Scalar::Dictionary(id)
            }
            5..=8 => {
                let width = if tag == 5 || tag == 7 { 4 } else { 8 };
                let slot = usize::from(width == 8);
                if tag <= 6 {
                    previous[slot] = previous[slot].wrapping_add(unzig(args.var()?) as u64);
                    if width == 4 && previous[slot] > u32::MAX as u64 {
                        return Err("joint numeric overflow".into());
                    }
                } else {
                    let mut b = [0; 8];
                    b[8 - width..].copy_from_slice(args.take(width)?);
                    previous[slot] = u64::from_be_bytes(b);
                }
                Scalar::Literal(previous[slot].to_be_bytes()[8 - width..].to_vec())
            }
            _ => return Err("joint tag".into()),
        })?;
    }
    args.end()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numeric_stream_crosses_width_boundaries_and_preserves_opaque_values() {
        let vals = vec![
            Some(u32::MAX.to_be_bytes().to_vec()),
            Some(0u32.to_be_bytes().to_vec()),
            Some(u64::MAX.to_be_bytes().to_vec()),
            Some(0u64.to_be_bytes().to_vec()),
            Some(vec![42; 20]),
            Some(vec![9; 7]),
            None,
        ];
        let ids = HashMap::from([(vec![42; 20], 0)]);
        let bytes = encode(&vals, &vec![None; vals.len()], &ids, true).unwrap();
        let out = decode(&bytes, vals.len(), 1).unwrap();
        for (i, x) in out.into_iter().enumerate() {
            match x {
                Scalar::Literal(v) => assert_eq!(Some(v), vals[i]),
                Scalar::Dictionary(id) => assert_eq!(id, 0),
                Scalar::Repeat => assert!(vals[i].is_none()),
                _ => panic!("unexpected delta"),
            }
        }
        assert!(decode(&bytes, vals.len() - 1, 1).is_err());
        assert!(decode(&bytes, vals.len(), 0).is_err());
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n], vals.len(), 1).is_err());
        }
    }
    #[test]
    fn context_delta_does_not_change_column_predictor() {
        let values = vec![
            Some(100u64.to_be_bytes().to_vec()),
            Some(9000u64.to_be_bytes().to_vec()),
            Some(101u64.to_be_bytes().to_vec()),
        ];
        let bytes = encode(&values, &[None, Some((8, 2)), None], &HashMap::new(), true).unwrap();
        let out = decode(&bytes, 3, 0).unwrap();
        assert!(matches!(out[1], Scalar::ContextDelta(8, 2)));
        assert!(matches!(&out[2],Scalar::Literal(v) if v==&101u64.to_be_bytes()));
    }
    #[test]
    fn recent_dictionary_handles_hits_eviction_and_invalid_position() {
        let ids: HashMap<_, _> = (0..20).map(|i| (vec![i as u8; 20], i)).collect();
        let order: Vec<_> = (0..20).chain([19, 18, 19, 0, 0, 19]).collect();
        let values: Vec<_> = order.iter().map(|&i| Some(vec![i as u8; 20])).collect();
        let data = encode_recent(&values, &vec![None; values.len()], &ids, false, true).unwrap();
        for (item, &expected) in decode(&data, values.len(), 20).unwrap().iter().zip(&order) {
            assert!(matches!(item,Scalar::Dictionary(id) if *id==expected));
        }
        let mut bad = vec![];
        blob(&mut bad, &[9]);
        blob(&mut bad, &[0]);
        assert!(decode(&bad, 1, 20).is_err());
    }
    #[test]
    fn complete_joint_frame_preserves_contexts_fallbacks_and_wraps() {
        let mut patches = vec![];
        for (i, n) in [0u64, u64::MAX, 0, 1, 1, 7, u64::MAX - 1]
            .into_iter()
            .enumerate()
        {
            let mut value = vec![0x24];
            value.extend((i as u32).to_be_bytes());
            value.push(0x32);
            value.extend(n.to_be_bytes());
            patches.push(([3; 32], value));
        }
        patches.push(([4; 32], vec![0xff, 0x00, 0x99]));
        patches.push(([3; 32], vec![]));
        let rows = vec![Row {
            seq: 1,
            header: vec![8; 118],
            txs: vec![],
            patches,
        }];
        for adaptive in [false, true] {
            let (frame, _) = encode_block(
                &rows,
                Options {
                    joint: true,
                    adaptive,
                    split_shapes: true,
                    context_delta: true,
                    ..Options::default()
                },
            )
            .unwrap();
            assert_eq!(decode_block(&frame).unwrap(), rows);
            let mut bad = frame.clone();
            let n = bad.len() - 1;
            bad[n] ^= 1;
            assert!(decode_block(&bad).is_err());
        }
    }
}
