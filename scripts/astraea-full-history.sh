#!/bin/bash
# Full Astraea history: chunks of 32768 ledgers, top down, from the ledger
# just before the already published cold history to the first ledger of the
# XRPLA publication. Each chunk is downloaded (`astraea-xrpla fetch`, checking
# signature, digests, roots and chain), written right away as ASTJ5 cold
# segments (every ledger decoded back and compared), and the raw data is
# deleted. A finished chunk is the chunks/S directory plus the marker
# chunks/S.ok ("S E transactions"); scripts/astraea-full-publish.py groups,
# indexes and publishes them. A rerun continues: finished chunks are skipped.
# Segment size depends on the chunk's volume: old, nearly empty ledgers go
# into segments of up to 32768 ledgers, recent ones into segments of 4096.
# A STOP file in the directory means no new chunks are started (low on space).
set -u
B=${B:-${ASTRAEA_HOME:-/var/lib/astraea}/src/target/release}
R=${R:-${ASTRAEA_HOME:-/var/lib/astraea}/history-full}
T=${T:-${ASTRAEA_HOME:-/var/lib/astraea}/tmp}
TOP=${TOP:?set TOP to the ledger just below the history already served}
BOTTOM=${BOTTOM:-32571}
CHUNK=32768
MIN_FREE_GB=${MIN_FREE_GB:-300}
MIN_TMP_GB=${MIN_TMP_GB:-50}
STREAMS=${STREAMS:-8}
mkdir -p $R/chunks $R/logs $T

chunk() {
  e=$1; s=$(( e - CHUNK + 1 )); [ $s -lt $BOTTOM ] && s=$BOTTOM
  # One process per chunk, even with two loaders running: the lock lives as
  # long as this shell, and the done markers are checked under it.
  exec 9>$R/chunks/$s.lock
  flock -n 9 || { echo "$s: busy in another loader"; return 0; }
  [ -f $R/chunks/$s.ok ] || [ -f $R/chunks/$s.moved ] && return 0
  [ -f $R/STOP ] && { echo "$s: STOP"; return 0; }
  # Free space is checked here too: the publisher only checks it between runs.
  for d in "$R $MIN_FREE_GB" "$T $MIN_TMP_GB"; do
    set -- $d; free=$(df --output=avail -B1G $1 | tail -1)
    [ ${free:-0} -lt $2 ] && { echo "$free GB free on $1" > $R/STOP; echo "$s: STOP, $1"; return 0; }
  done
  rm -f $R/chunks/$s.fail; rm -rf $R/chunks/$s; mkdir -p $R/chunks/$s
  x=$T/$s.$$.xwcp
  ok=
  # fetch retries single requests itself; a chunk is retried with a growing
  # pause (1 to 6 minutes) for longer outages of the publication server.
  for try in 1 2 3 4 5 6; do
    if nice -n 10 $B/astraea-xrpla fetch --from $s --to $e --out $x > $R/logs/$s.fetch.log 2>&1; then ok=1; break; fi
    sleep $(( 60 * try ))
  done
  if [ -z "$ok" ]; then
    echo "fetch: $(tail -1 $R/logs/$s.fetch.log)" > $R/chunks/$s.fail; rm -f $x; echo "$s FETCH FAILED"; return 1
  fi
  mb=$(grep -oE "downloaded [0-9]+" $R/logs/$s.fetch.log | tail -1 | awk '{print $2}')
  r=$(( 1000 / (${mb:-1000} + 1) )); seg=4096
  while [ $r -ge 2 ] && [ $seg -lt 32768 ]; do seg=$(( seg * 2 )); r=$(( r / 2 )); done
  if ! /usr/bin/time -v nice -n 10 $B/astraea-state --db /nonexistent history-cold $x --to $R/chunks/$s \
      --kinds not-recorded --segment-ledgers $seg > $R/logs/$s.cold.log 2> $R/logs/$s.cold.time; then
    echo "write: $(grep -v '^\s' $R/logs/$s.cold.time | head -1)" > $R/chunks/$s.fail; rm -f $x; echo "$s COLD FAILED"; return 1
  fi
  rm -f $x
  # The chunk must hold every ledger of its range, not just what was read.
  n=$(grep -oE "^total [0-9]+ ledgers" $R/logs/$s.cold.log | awk '{print $2}')
  if [ "${n:-0}" -ne $(( e - s + 1 )) ]; then
    echo "write: ${n:-0} ledgers instead of $(( e - s + 1 ))" > $R/chunks/$s.fail; echo "$s INCOMPLETE"; return 1
  fi
  tx=$(grep -oE "[0-9]+ transactions" $R/logs/$s.cold.log | tail -1 | awk '{print $1}')
  echo "$s $e ${tx:-0}" > $R/chunks/$s.ok.tmp && mv $R/chunks/$s.ok.tmp $R/chunks/$s.ok
  echo "$s..$e: segment $seg, $(tail -1 $R/logs/$s.cold.log | sed 's/^total //') $(grep 'Maximum resident' $R/logs/$s.cold.time | awk '{print $NF}') KB"
}
export -f chunk; export B R T BOTTOM CHUNK MIN_FREE_GB MIN_TMP_GB
seq $TOP -$CHUNK $BOTTOM | xargs -P $STREAMS -I{} bash -c 'chunk {}'
echo "== chunks: $(ls $R/chunks/*.ok $R/chunks/*.moved 2>/dev/null | wc -l) done, $(ls $R/chunks/*.fail 2>/dev/null | wc -l) failed"
