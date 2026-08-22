#!/bin/sh
# IXFR / journal integration rig: tdns-auth primary -> BIND9 secondary.
#
# Covers what a single-server rig cannot: that a journalled change reaches a
# REAL secondary, that it does so incrementally, and that a restart which
# replays the journal does not strand the secondary or move a serial backwards.
#
# Everything lives under $R and on loopback ports 5400/8400/5401, chosen to stay
# clear of anything else a test host may already be serving.

R=/var/tmp/ixfrtest
# Which tree to run against. Override to A/B a change against the tree it was
# cut from, which is the only way to know the rig tests what it claims:
#
#   SRC=/src/git/tdns ./run-ixfr-tests.sh             # the default
#   git -C /src/git/tdns worktree add --detach /src/git/tdns.ctl <commit>
#   cp cmdv2/algs-env.mk + each app's {algs-libs.mk,*_algs.go} across, make, then
#   SRC=/src/git/tdns.ctl ./run-ixfr-tests.sh
#
# Section H was written that way: 88/88 on the branch, 15 failures on the commit
# it was cut from, including #362's two symptoms verbatim.
SRC=${SRC:-/src/git/tdns}
PRIM=127.0.0.1
PPORT=5400
SPORT=5401
ZONE=rig.example.
DIG="/usr/pkg/bin/dig +time=2 +tries=1"
CLI="$SRC/cmdv2/cli/tdns-cli --config $R/tdns-cli.yaml"

# Fail here rather than three sections in. An SRC that is unset, stale or simply
# not built produces a run that looks like a product failure: the daemon never
# comes up, every assertion about it fails, and the reason is a missing binary.
for _b in "$SRC/cmdv2/auth/tdns-auth" "$SRC/cmdv2/cli/tdns-cli"; do
  [ -x "$_b" ] && continue
  echo "no executable at $_b" >&2
  echo "set SRC to a tdns worktree whose cmdv2/auth and cmdv2/cli have been built with make" >&2
  exit 2
done

# Every run uses fresh record names. Adding an RR that is already present is a
# no-op -- correctly, since RFC 2136 adds are idempotent -- so a fixed name
# makes the suite pass once against a virgin zone and then quietly stop
# exercising anything: no serial change, no delta, nothing to replay.
RUN=$(date +%H%M%S)

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS $*"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL $*"; }
note() { echo; echo "--- $*"; }

# A serial is digits, or nothing. dig prints its failures as text, and an
# earlier version of this helper handed that text back as if it were a serial:
# comparisons then compared garbage, and the readiness wait in restart_primary
# read "no servers could be reached" as "the daemon is up" and returned early.
soa() {
  _s=$($DIG @127.0.0.1 -p "$1" +short "$ZONE" soa 2>/dev/null | awk "{print \$3}" | head -1)
  case "$_s" in
    ""|*[!0-9]*) echo "" ;;
    *)           echo "$_s" ;;
  esac
}
rr()  { $DIG @127.0.0.1 -p "$1" +short "$2" "$3" 2>/dev/null | head -1; }

# Wait for a port to serve a serial at least as new as $2. Polling, not a fixed
# sleep: NOTIFY propagation is event-driven and a sleep long enough to be safe
# would make the suite slow enough not to be run.
wait_serial() {
  _p=$1; _want=$2; _n=0
  while [ $_n -lt 40 ]; do
    _s=$(soa "$_p")
    [ -n "$_s" ] && [ "$_s" -ge "$_want" ] 2>/dev/null && return 0
    _n=$((_n+1)); sleep 0.5
  done
  return 1
}

journal_deltas() {
  $CLI auth zone journal status --zone "$ZONE" 2>/dev/null |
    awk '/journal is empty/ {print 0; exit} /deltas:/ {print $2; exit}'
}

# Restart the primary, and PROVE it restarted by watching the pid change.
#
# Without that proof the whole suite is suspect: if pkill has not finished when
# the replacement starts, the new process fails to bind, the OLD one keeps
# serving, and every "survived the restart" assertion passes while testing
# nothing at all.
restart_primary() {
  _cfg=${1:-$R/tdns-auth.yaml}
  _old=$(pgrep -f "tdns-auth --config $R/" 2>/dev/null | head -1)

  pkill -f "tdns-auth --config $R/" 2>/dev/null
  _n=0
  while [ $_n -lt 30 ] && pgrep -f "tdns-auth --config $R/" >/dev/null 2>&1; do
    _n=$((_n+1)); sleep 0.5
  done
  pgrep -f "tdns-auth --config $R/" >/dev/null 2>&1 && return 1   # refused to die

  ( cd $SRC/cmdv2/auth && nohup ./tdns-auth --config $_cfg \
      >> $R/log/stdout.log 2>&1 & )

  _n=0
  while [ $_n -lt 40 ]; do
    _new=$(pgrep -f "tdns-auth --config $R/" 2>/dev/null | head -1)
    if [ -n "$_new" ] && [ "$_new" != "$_old" ] && [ -n "$(soa $PPORT)" ]; then
      return 0
    fi
    _n=$((_n+1)); sleep 0.5
  done
  return 1
}

# How the secondary last transferred: IXFR or AXFR. Read from named own log,
# which is the only place that distinguishes them honestly.
last_xfer_kind() {
  grep -Eo "requesting (IXFR|AXFR)" $R/named/xfer.log 2>/dev/null | tail -1 | awk "{print \$2}"
}

echo "=== IXFR / journal rig ==="
echo "primary  127.0.0.1:$PPORT   secondary 127.0.0.1:$SPORT   zone $ZONE"

# Reset BOTH sides to a known state.
#
# The primary, because section F deliberately restarts with persistence off and
# any manual poking leaves the rig wherever it was left.
#
# The secondary, because F's whole point is that the primary REGRESSES while the
# secondary does not follow -- so BIND ends a run holding a higher serial, and
# richer content, than the primary starts the next one with. It then refuses to
# transfer (serials only move forward) and answers from a copy that no longer
# matches, which shows up as unrelated failures three sections later.
reset_rig() {
  restart_primary $R/tdns-auth.yaml || return 1

  pkill -f "named -c $R/named/named.conf" 2>/dev/null
  _n=0
  while [ $_n -lt 20 ] && pgrep -f "named -c $R/named/named.conf" >/dev/null 2>&1; do
    _n=$((_n+1)); sleep 0.5
  done
  rm -f $R/named/rig.example.db $R/named/rig.example.db.jnl
  nohup /usr/pkg/sbin/named -c $R/named/named.conf -f >> $R/named/stdout.log 2>&1 &

  # Wait for the fresh AXFR to land.
  _n=0
  while [ $_n -lt 60 ]; do
    [ -n "$(soa $SPORT)" ] && return 0
    _n=$((_n+1)); sleep 0.5
  done
  return 1
}

if reset_rig; then
  echo "(rig reset: primary on default config, secondary re-transferred)"
else
  echo "WARNING: could not reset the rig"
fi

note "A. baseline"
P0=$(soa $PPORT); S0=$(soa $SPORT)
[ -n "$P0" ] && ok "primary serves ($P0)" || bad "primary does not answer"
[ -n "$S0" ] && ok "secondary serves ($S0)" || bad "secondary does not answer"
[ "$P0" = "$S0" ] && ok "secondary is converged" || bad "serial mismatch: primary $P0, secondary $S0"

note "B. an API update reaches the secondary incrementally"
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "b1-$RUN.$ZONE 300 IN A 10.2.0.1" >/dev/null 2>&1
P1=$(soa $PPORT)
[ "$P1" -gt "$P0" ] 2>/dev/null && ok "primary serial advanced ($P0 -> $P1)" \
  || bad "primary serial did not advance ($P0 -> $P1)"
if wait_serial $SPORT "$P1"; then ok "secondary converged to $P1"
else bad "secondary did not reach $P1 (stuck at $(soa $SPORT))"; fi
[ "$(rr $SPORT b1-$RUN.$ZONE a)" = "10.2.0.1" ] && ok "secondary answers the new record" \
  || bad "secondary does not answer the new record"
K=$(last_xfer_kind)
[ "$K" = "IXFR" ] && ok "transfer was incremental (IXFR)" \
  || bad "transfer was $K, expected IXFR"
D=$(journal_deltas)
[ "${D:-0}" -gt 0 ] 2>/dev/null && ok "journal recorded the change ($D delta(s))" \
  || bad "journal is empty after an update"

note "C. sync folds the journal into the zone file"
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1
D=$(journal_deltas)
[ "${D:-1}" = "0" ] && ok "journal empty after sync" || bad "journal still holds $D delta(s) after sync"
grep -q "b1-$RUN.rig.example" $R/zones/rig.example 2>/dev/null \
  && ok "the change is in the zone file on disk" || bad "the zone file lacks the change"

note "D. restart replays the journal, and the secondary re-converges"
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "d1-$RUN.$ZONE 300 IN A 10.4.0.1" >/dev/null 2>&1
P2=$(soa $PPORT)
wait_serial $SPORT "$P2" || true
S2=$(soa $SPORT)
D=$(journal_deltas)
[ "${D:-0}" -gt 0 ] 2>/dev/null && ok "journal holds the un-synced change" \
  || bad "journal empty before the restart -- the test would prove nothing"

if restart_primary; then ok "primary restarted"; else bad "primary did not come back"; fi
P3=$(soa $PPORT)
[ "$(rr $PPORT d1-$RUN.$ZONE a)" = "10.4.0.1" ] \
  && ok "THE CHANGE SURVIVED THE RESTART (journal replayed)" \
  || bad "the change was lost across the restart"
[ "$P3" -ge "$S2" ] 2>/dev/null && ok "serial did not go backwards ($S2 -> $P3)" \
  || bad "SERIAL WENT BACKWARDS: secondary had $S2, primary now $P3"
if wait_serial $SPORT "$P3"; then ok "secondary re-converged after the replay ($P3)"
else bad "secondary stranded at $(soa $SPORT), primary at $P3"; fi
[ "$(rr $SPORT d1-$RUN.$ZONE a)" = "10.4.0.1" ] \
  && ok "secondary has the replayed record" || bad "secondary lacks the replayed record"

note "E. freeze refuses updates, thaw restores them"
$CLI auth zone freeze --zone "$ZONE" >/dev/null 2>&1
if $CLI auth zone update addrr --zone "$ZONE" --via api \
     --rr "e1-$RUN.$ZONE 300 IN A 10.5.0.1" 2>&1 | grep -qi "frozen"; then
  ok "a frozen zone refuses updates, and says why"
else bad "a frozen zone accepted an update (or refused it for the wrong reason)"; fi
$CLI auth zone thaw --zone "$ZONE" >/dev/null 2>&1
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "e1-$RUN.$ZONE 300 IN A 10.5.0.1" >/dev/null 2>&1
[ "$(rr $PPORT e1-$RUN.$ZONE a)" = "10.5.0.1" ] && ok "updates work again after thaw" \
  || bad "updates still refused after thaw"


note "F. the kill-switch: journal: active: false"
# The escape hatch added in fedcf07. It exists for the case where persistence
# itself misbehaves and updates must keep flowing until a fix ships, so what
# matters is that OFF means "applied but not durable" -- not "refused", and not
# "silently still recording".
sed -e '$a\
journal:\
   active: false' $R/tdns-auth.yaml > $R/tdns-auth-nojournal.yaml

SF0=$(soa $SPORT)
if restart_primary $R/tdns-auth-nojournal.yaml; then
  ok "primary restarted with persistence disabled"
else
  bad "primary did not come back with persistence disabled"
fi

# Count BEFORE, not zero. Deltas from earlier sections are still in the journal
# -- correctly, since turning the switch off must not discard what was already
# recorded. The property under test is that nothing NEW is added.
D0=$(journal_deltas)
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "f1-$RUN.$ZONE 300 IN A 10.6.0.1" >/dev/null 2>&1
[ "$(rr $PPORT f1-$RUN.$ZONE a)" = "10.6.0.1" ] \
  && ok "the update still APPLIED with the switch off" \
  || bad "the kill-switch refused the update; off must mean not-durable, not not-allowed"

D1=$(journal_deltas)
[ "$D1" = "$D0" ] && ok "nothing new was recorded (journal still $D1 delta(s))" \
  || bad "the switch is off but the journal grew: $D0 -> $D1"

# The documented consequence, asserted rather than assumed: with nothing
# recorded, a restart loses THIS change -- while any pre-existing journal still
# replays, which is why the other records come back.
if restart_primary $R/tdns-auth-nojournal.yaml; then ok "primary restarted again"
else bad "primary did not come back"; fi
[ -z "$(rr $PPORT f1-$RUN.$ZONE a)" ] \
  && ok "the un-journalled change is GONE after the restart (as designed)" \
  || bad "the change survived despite the journal being off -- it was recorded somewhere"

# And the secondary does not follow the primary backwards, because serials only
# move forward. Compared against the SECONDARY's own earlier serial: comparing
# against the primary's would fail merely because the secondary had not yet
# caught up when the section began.
SF1=$(soa $SPORT)
[ -n "$SF1" ] && [ "$SF1" -ge "${SF0:-0}" ] 2>/dev/null \
  && ok "secondary held its serial ($SF0 -> $SF1); it does not follow a regression" \
  || bad "secondary went backwards: $SF0 -> $SF1"

# Leave the rig on its normal config, persistence on.
if restart_primary $R/tdns-auth.yaml; then ok "rig restored to its default config"
else bad "could not restore the default config"; fi

note "G. reconciliation: the zone file is EDITED under a running server"
# Sections A-F all test a journal whose chain still starts at the file it was
# computed against. This section breaks that assumption deliberately, because
# an operator who edits or redeploys a zone file breaks it too, and before
# reconciliation that state cost the zone every journalled change.
#
# A conflict has exactly one shape: a record the NEW file still contains that
# the journal DELETES. Manufacture it rather than hope to stumble into it.
#
# The file has to be CHANGED in tdns's sense: a different content digest from
# the one it recorded when it last read or wrote the file. Restoring a copy
# that tdns itself wrote does NOT qualify -- API updates never rewrite the zone
# file, so the copy is byte-identical and the server correctly says unchanged,
# takes the plain replay path, and none of this is exercised.
edit_zonefile() {
  awk -v add="$1" 'BEGIN{OFS="\t"} !d && $4=="SOA" {$7=$7+1; d=1} {print} END{print add}' \
    $R/zones/rig.example > $R/zones/rig.example.edited \
    && mv $R/zones/rig.example.edited $R/zones/rig.example
}

# Fold everything in, so the journal starts empty against a known file.
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1

# The victim has to live IN THE FILE, so add it and fold that in too.
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "g-vict-$RUN.$ZONE 300 IN A 10.7.0.1" >/dev/null 2>&1
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1
grep -q "g-vict-$RUN" $R/zones/rig.example \
  && ok "setup: the victim record is in the zone file" \
  || bad "setup: the victim never reached the zone file"

# Diverge the journal from the file: DEL the victim (which the file still
# holds -> conflict) and ADD a keeper (no conflict -> must survive the merge).
$CLI auth zone update delrr --zone "$ZONE" --via api \
  --rr "g-vict-$RUN.$ZONE 300 IN A 10.7.0.1" >/dev/null 2>&1
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "g-keep-$RUN.$ZONE 300 IN A 10.7.0.2" >/dev/null 2>&1

[ -z "$(rr $PPORT g-vict-$RUN.$ZONE a)" ] \
  && ok "setup: the victim is gone from the live zone" \
  || bad "setup: the victim is still served after delrr"
[ "$(rr $PPORT g-keep-$RUN.$ZONE a)" = "10.7.0.2" ] \
  && ok "setup: the keeper is live" || bad "setup: the keeper was not applied"
GD=$(journal_deltas)
[ "${GD:-0}" -gt 0 ] 2>/dev/null \
  && ok "setup: journal holds the divergence ($GD delta(s))" \
  || bad "setup: journal empty -- the merge would have nothing to reconcile"

wait_serial $SPORT "$(soa $PPORT)" || true
SG=$(soa $SPORT)          # what the secondary already holds, for the floor check

rm -f $R/zones/rig.example.*.rejected
edit_zonefile "g-file-$RUN.$ZONE 300 IN A 10.8.0.1"
if restart_primary; then ok "primary restarted over an EDITED zone file"
else bad "primary did not come back after the file was edited"; fi

# Assert the edit actually took effect, or every assertion below could pass
# against a file nobody changed.
[ "$(rr $PPORT g-file-$RUN.$ZONE a)" = "10.8.0.1" ] \
  && ok "the edited file's new record is being served" \
  || bad "the edit did not reach the served zone -- the rest of G proves nothing"

# The point of the whole feature: an edited file does not cost the journal.
[ "$(rr $PPORT g-keep-$RUN.$ZONE a)" = "10.7.0.2" ] \
  && ok "THE JOURNAL SURVIVED AN EDITED FILE (non-conflicting ADD is live)" \
  || bad "the journal was discarded when the file changed: the keeper is gone"

# db-wins is the default when neither option is set.
[ -z "$(rr $PPORT g-vict-$RUN.$ZONE a)" ] \
  && ok "db-wins: the file's record lost; it stays deleted" \
  || bad "db-wins: the edited file resurrected a record the journal deleted"

# ...and the losing record is not lost silently.
ART=$(ls $R/zones/rig.example.*.rejected 2>/dev/null | tail -1)
[ -n "$ART" ] && ok "a .rejected artefact was written ($(basename $ART))" \
  || bad "conflicts were resolved with no .rejected artefact"
if [ -n "$ART" ] && grep -q "^ADD g-vict-$RUN" "$ART" 2>/dev/null; then
  ok "the artefact holds the losing record as an ADD instruction"
else
  bad "the artefact does not carry the losing record as an ADD"
fi

# The operator-facing report has to name the side that actually lost. Pointing
# them at an artefact while describing the opposite of what is in it is worse
# than saying nothing.
LMSG=$(grep "lost where the two disagreed" $R/log/tdns.log 2>/dev/null | tail -1)
case "$LMSG" in
  *"records from the FILE lost"*) ok "db-wins: the report names the FILE as the loser" ;;
  *) bad "db-wins: the conflict report does not name the file as the loser: $LMSG" ;;
esac

# The serial floor: a merge must publish clear of what secondaries hold, or
# they ignore it forever -- a secondary refreshes on a serial increase only.
PG2=$(soa $PPORT)
[ -n "$PG2" ] && [ "$PG2" -gt "${SG:-0}" ] 2>/dev/null \
  && ok "the merge published CLEAR of the secondary's serial ($SG -> $PG2)" \
  || bad "SERIAL FLOOR FAILED: secondary holds $SG, primary published $PG2"
if wait_serial $SPORT "$PG2"; then ok "secondary followed the merge to $PG2"
else bad "secondary STRANDED at $(soa $SPORT) while primary serves $PG2"; fi
[ "$(rr $SPORT g-keep-$RUN.$ZONE a)" = "10.7.0.2" ] \
  && ok "secondary has the merged content" || bad "secondary lacks the merged content"

note "G2. the .rejected artefact is an update, and feeds straight back"
# The artefact's own header tells the operator to replay it. If that does not
# work the artefact is a receipt for a loss rather than a way to undo it.
if [ -n "$ART" ]; then
  $CLI auth zone update from-file --file "$ART" --zone "$ZONE" --via api >/dev/null 2>&1
  [ "$(rr $PPORT g-vict-$RUN.$ZONE a)" = "10.7.0.1" ] \
    && ok "replaying the artefact restored the record that lost" \
    || bad "the artefact did not replay: the loss is not reversible"
else
  bad "no artefact to replay"
fi

note "G3. re-anchoring: an unedited file does not merge twice"
# After a merge the journal is re-anchored to the file now in hand. Without
# that, every subsequent restart re-merges the same file forever.
NB=$(ls $R/zones/rig.example.*.rejected 2>/dev/null | wc -l | tr -d ' ')
if restart_primary; then ok "primary restarted with the file untouched"
else bad "primary did not come back"; fi
NA=$(ls $R/zones/rig.example.*.rejected 2>/dev/null | wc -l | tr -d ' ')
[ "$NA" = "$NB" ] && ok "no second merge on an unedited file (artefacts still $NA)" \
  || bad "it merged again on an unedited file: $NB -> $NA artefacts"
[ "$(rr $PPORT g-keep-$RUN.$ZONE a)" = "10.7.0.2" ] \
  && ok "content is stable across the second restart" \
  || bad "content changed on a restart that should have been a plain replay"

note "G4. explicit reload takes the same path as startup"
# The design doc states this outright -- "Startup and explicit reload take the
# same path" -- on the grounds that two behaviours for one situation is how
# this class of bug returns. Assert the documented contract.
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "g-rel-$RUN.$ZONE 300 IN A 10.9.0.1" >/dev/null 2>&1
[ "$(rr $PPORT g-rel-$RUN.$ZONE a)" = "10.9.0.1" ] \
  && ok "setup: the reload keeper is live and journalled" \
  || bad "setup: the reload keeper was not applied"

edit_zonefile "g-rfile-$RUN.$ZONE 300 IN A 10.9.0.2"
$CLI auth zone reload --zone "$ZONE" >/dev/null 2>&1
sleep 3
[ "$(rr $PPORT g-rfile-$RUN.$ZONE a)" = "10.9.0.2" ] \
  && ok "reload picked up the edited file" \
  || bad "reload did not read the edited file at all"
[ "$(rr $PPORT g-rel-$RUN.$ZONE a)" = "10.9.0.1" ] \
  && ok "reload kept the journalled change (same path as startup)" \
  || bad "reload DISCARDED the journal: startup and reload do NOT take the same path"

note "G5. on-conflict-zonefile-wins reverses the outcome"
sed -e 's/inline-signing \]/inline-signing, on-conflict-zonefile-wins ]/' \
    $R/tdns-auth.yaml > $R/tdns-auth-zfwins.yaml
grep -q "on-conflict-zonefile-wins" $R/tdns-auth-zfwins.yaml \
  && ok "setup: built a zonefile-wins config" \
  || bad "setup: could not build a zonefile-wins config"

# Fresh conflict, same shape: a record in the file that the journal deletes.
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "g-zf-$RUN.$ZONE 300 IN A 10.10.0.1" >/dev/null 2>&1
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1
$CLI auth zone update delrr --zone "$ZONE" --via api \
  --rr "g-zf-$RUN.$ZONE 300 IN A 10.10.0.1" >/dev/null 2>&1
[ -z "$(rr $PPORT g-zf-$RUN.$ZONE a)" ] \
  && ok "setup: the zonefile-wins victim is deleted in the live zone" \
  || bad "setup: the zonefile-wins victim is still served"

rm -f $R/zones/rig.example.*.rejected
edit_zonefile "g-zfile-$RUN.$ZONE 300 IN A 10.10.0.2"
if restart_primary $R/tdns-auth-zfwins.yaml; then
  ok "primary restarted with on-conflict-zonefile-wins"
else bad "primary did not come back under zonefile-wins"; fi

[ "$(rr $PPORT g-zfile-$RUN.$ZONE a)" = "10.10.0.2" ] \
  && ok "the zonefile-wins edit is being served" \
  || bad "the zonefile-wins edit did not load"
[ "$(rr $PPORT g-zf-$RUN.$ZONE a)" = "10.10.0.1" ] \
  && ok "zonefile-wins: the FILE's record won; the journal's DEL was dropped" \
  || bad "zonefile-wins had no effect: the journal's DEL still won"
ART2=$(ls $R/zones/rig.example.*.rejected 2>/dev/null | tail -1)
if [ -n "$ART2" ] && grep -q "^DEL g-zf-$RUN" "$ART2" 2>/dev/null; then
  ok "the artefact holds the dropped instruction as a DEL"
else
  bad "zonefile-wins wrote no artefact naming the instruction that lost"
fi

LMSG2=$(grep "lost where the two disagreed" $R/log/tdns.log 2>/dev/null | tail -1)
case "$LMSG2" in
  *"changes from the JOURNAL lost"*) ok "zonefile-wins: the report names the JOURNAL as the loser" ;;
  *) bad "zonefile-wins: the report still blames the file, contradicting the artefact: $LMSG2" ;;
esac

# Back to the default config for whatever runs next.
if restart_primary $R/tdns-auth.yaml; then ok "rig restored to the default config"
else bad "could not restore the default config"; fi
echo

note "H. reload: the same path as startup, on a RUNNING server"
# G through G5 drive reconciliation through RESTARTS. That is the easy half:
# a restart re-reads the file unconditionally, so the only question is what it
# then does with the journal. The reload path has to decide something a restart
# never does -- whether to read the file AT ALL -- and it used to decide that
# by comparing SOA serials, which is #362. This section covers what only the
# reload path can get wrong.
#
# --error is used throughout instead of a sleep: it waits for the refresh to
# finish and reports parse errors, so an assertion cannot race the reload it is
# asserting about.
reload()      { $CLI auth zone reload --zone "$ZONE" --error --timeout 20s 2>&1; }
file_serial() { awk '$4=="SOA" {print $7; exit}' $R/zones/rig.example; }
zonefile_sum(){ cksum < $R/zones/rig.example; }

# Append a record and leave the SOA serial exactly where it is. The whole point
# of #362 is that this must still be noticed: detection is on a content digest,
# so a serial an operator forgot to bump cannot hide an edit.
append_norebump() { printf '%s\n' "$1" >> $R/zones/rig.example; }

# Same zone, different bytes: every record reversed in order, with comments
# added. A byte hash would call this a change and force a needless republish
# and a needless transfer to every secondary; a content digest must not.
# Whole lines are moved, never rewritten, so nothing about the zone changes.
reorder_zonefile() {
  { echo "; reordered by the rig -- same records, different order"
    awk '{ a[NR]=$0 } END { for (i=NR; i>=1; i--) print a[i] }' $R/zones/rig.example
    echo "; end of reordering"
  } > $R/zones/rig.example.reordered && mv $R/zones/rig.example.reordered $R/zones/rig.example
}

# Start from a known state: file current, journal empty.
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1

note "H1. an edit that does NOT move the SOA serial is picked up"
# Symptom 1 of #362. The refresh compared the file's serial with the last one
# it read, so an edit that left the serial alone was not read at all -- and
# `zone reload` reported success having done nothing. The change then appeared
# at some later restart that nobody associated with the edit.
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "h1-keep-$RUN.$ZONE 300 IN A 10.11.0.1" >/dev/null 2>&1
[ "$(rr $PPORT h1-keep-$RUN.$ZONE a)" = "10.11.0.1" ] \
  && ok "setup: the journalled keeper is live" || bad "setup: the keeper was not applied"
HD=$(journal_deltas)
[ "${HD:-0}" -gt 0 ] 2>/dev/null && ok "setup: the journal holds it ($HD delta(s))" \
  || bad "setup: journal empty -- H1 would prove nothing about the journal"

FS0=$(file_serial)
PH0=$(soa $PPORT)
append_norebump "h1-file-$RUN.$ZONE 300 IN A 10.11.0.2"
[ "$(file_serial)" = "$FS0" ] \
  && ok "setup: the edit left the file's serial at $FS0" \
  || bad "setup: the edit moved the file's serial, which is not the case under test"

reload >/dev/null 2>&1
[ "$(rr $PPORT h1-file-$RUN.$ZONE a)" = "10.11.0.2" ] \
  && ok "RELOAD PICKED UP AN EDIT WITH NO SERIAL BUMP" \
  || bad "the edit was ignored because its serial had not moved (#362 symptom 1)"
[ "$(rr $PPORT h1-keep-$RUN.$ZONE a)" = "10.11.0.1" ] \
  && ok "the reload kept the journalled change" \
  || bad "the reload discarded the journal"

# The served serial MUST move even though the file's did not, or no secondary
# ever learns about the edit: they refresh on a serial increase and nothing else.
PH1=$(soa $PPORT)
[ -n "$PH1" ] && [ "$PH1" -gt "$PH0" ] 2>/dev/null \
  && ok "the served serial advanced ($PH0 -> $PH1) though the file's did not" \
  || bad "the served serial did not move ($PH0 -> $PH1); no secondary would follow"
if wait_serial $SPORT "$PH1"; then ok "secondary followed the reload to $PH1"
else bad "secondary stranded at $(soa $SPORT), primary at $PH1"; fi
[ "$(rr $SPORT h1-file-$RUN.$ZONE a)" = "10.11.0.2" ] \
  && ok "secondary has the edit" || bad "secondary lacks the edit"
[ "$(rr $SPORT h1-keep-$RUN.$ZONE a)" = "10.11.0.1" ] \
  && ok "secondary has the journalled change too" || bad "secondary lacks the journalled change"

note "H2. a reload does not leave the zone unable to accept updates"
# Symptom 2 of #362, and the more destructive one. A reload adopts the new file
# as the journal's anchor but used to bump the served serial by one, so a file
# whose serial had been moved WELL PAST what was being served left the anchor
# above the zone. The next update was then a delta from the file's serial to a
# lower one, which is refused -- and the zone accepted nothing further until it
# was restarted.
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1
PH2=$(soa $PPORT)
JUMP=$((PH2 + 25))
awk -v s="$JUMP" 'BEGIN{OFS="\t"} !d && $4=="SOA" {$7=s; d=1} {print}' \
  $R/zones/rig.example > $R/zones/rig.example.jump \
  && mv $R/zones/rig.example.jump $R/zones/rig.example
echo "h2-file-$RUN.$ZONE 300 IN A 10.12.0.1" >> $R/zones/rig.example
[ "$(file_serial)" = "$JUMP" ] \
  && ok "setup: the file's serial jumped past the served one ($PH2 -> $JUMP)" \
  || bad "setup: could not move the file's serial ahead"

reload >/dev/null 2>&1
[ "$(rr $PPORT h2-file-$RUN.$ZONE a)" = "10.12.0.1" ] \
  && ok "the jumped-ahead file was loaded" || bad "the jumped-ahead file was not loaded"

PH3=$(soa $PPORT)
[ -n "$PH3" ] && [ "$PH3" -gt "$JUMP" ] 2>/dev/null \
  && ok "the reload published CLEAR of the file's serial ($JUMP -> $PH3)" \
  || bad "SERIAL FLOOR FAILED: file says $JUMP, zone serves $PH3"

# The assertion that matters: the zone still works afterwards.
UPOUT=$($CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "h2-after-$RUN.$ZONE 300 IN A 10.12.0.2" 2>&1)
[ "$(rr $PPORT h2-after-$RUN.$ZONE a)" = "10.12.0.2" ] \
  && ok "THE ZONE STILL ACCEPTS UPDATES AFTER THE RELOAD" \
  || bad "the zone is wedged after the reload: $UPOUT"
case "$UPOUT" in
  *"does not advance the serial"*)
    bad "the journal is anchored above the zone (#362 symptom 2)" ;;
  *)  ok "no delta was refused for failing to advance the serial" ;;
esac

note "H3. a reload that finds nothing changed does nothing"
# The refresh ticker takes this path on every refresh interval. A reload that
# republished each time would churn the serial and NOTIFY every secondary over
# a zone nobody touched.
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1
PH4=$(soa $PPORT)
reload >/dev/null 2>&1
PH5=$(soa $PPORT)
[ "$PH5" = "$PH4" ] && ok "an unchanged file left the serial alone ($PH4)" \
  || bad "an untouched zone republished on reload: $PH4 -> $PH5"

note "H4. reordering the file is not a change"
# Detection is on a ZONEMD digest of the CONTENT, not on the bytes. An operator
# who sorts, comments or reflows a file kept under revision control has changed
# nothing about the zone, and must not pay a republish and a zone transfer.
SUM_BEFORE=$(zonefile_sum)
reorder_zonefile
[ "$(zonefile_sum)" != "$SUM_BEFORE" ] \
  && ok "setup: the file's bytes really did change" \
  || bad "setup: the reorder did not change the file at all"
PH6=$(soa $PPORT)
reload >/dev/null 2>&1
PH7=$(soa $PPORT)
[ "$PH7" = "$PH6" ] && ok "REORDERING DID NOT COUNT AS A CHANGE (serial still $PH7)" \
  || bad "a reordered file republished: $PH6 -> $PH7 -- detection is on bytes, not content"
[ "$(rr $PPORT h1-keep-$RUN.$ZONE a)" = "10.11.0.1" ] \
  && ok "content is intact after the reorder" || bad "the reorder lost content"

note "H5. a reload is allowed while the journal holds unwritten changes"
# Both replay and merge mark the zone dirty at every load, so "the zone has
# been modified" is the ORDINARY state of a zone with a journal. Refusing a
# reload on that made the reconciliation path unreachable for exactly the zones
# it exists for. It is refused only when nothing but memory holds the changes.
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "h5-$RUN.$ZONE 300 IN A 10.13.0.1" >/dev/null 2>&1
[ "$(rr $PPORT h5-$RUN.$ZONE a)" = "10.13.0.1" ] \
  && ok "setup: the zone has an unwritten journalled change" \
  || bad "setup: the update was not applied"
ROUT=$(reload)
case "$ROUT" in
  *"not possible"*|*"has been modified"*|*"only memory holds"*)
    bad "the reload was refused on a zone whose journal holds the changes: $ROUT" ;;
  *)  ok "the reload was accepted on a dirty zone" ;;
esac
[ "$(rr $PPORT h5-$RUN.$ZONE a)" = "10.13.0.1" ] \
  && ok "and the journalled change is still served afterwards" \
  || bad "the reload discarded the journalled change"

note "H6. a reload does not rewrite the operator's zone file"
# The zone file is the operator's, written only when they ask -- write, sync or
# freeze. A merge leaves the zone dirty, and the refresh engine's write-back
# branch keys on dirty, so a reload that merged used to rewrite the file it had
# just read: ordering and comments gone, at the exact moment the operator had
# been editing it.
SUM_H6=$(zonefile_sum)
append_norebump "h6-file-$RUN.$ZONE 300 IN A 10.14.0.1"
SUM_H6_EDITED=$(zonefile_sum)
reload >/dev/null 2>&1
[ "$(rr $PPORT h6-file-$RUN.$ZONE a)" = "10.14.0.1" ] \
  && ok "setup: the reload adopted the edit (so the zone is dirty from the merge)" \
  || bad "setup: the edit was not adopted, so nothing here is under test"
[ "$(zonefile_sum)" = "$SUM_H6_EDITED" ] \
  && ok "THE ZONE FILE IS BYTE-IDENTICAL AFTER THE RELOAD" \
  || bad "the reload rewrote the operator's zone file"
grep -q "; reordered by the rig" $R/zones/rig.example \
  && ok "the operator's comments survived" \
  || bad "the file was rewritten: the comments are gone"

note "H7. a reload merges a conflict and reports what lost"
# The same conflict G proves across a restart, driven through a reload instead:
# a record the file still holds that the journal deletes.
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1
$CLI auth zone update addrr --zone "$ZONE" --via api \
  --rr "h7-vict-$RUN.$ZONE 300 IN A 10.15.0.1" >/dev/null 2>&1
$CLI auth zone sync --zone "$ZONE" >/dev/null 2>&1
sleep 1
grep -q "h7-vict-$RUN" $R/zones/rig.example \
  && ok "setup: the victim is in the zone file" || bad "setup: the victim never reached the file"
$CLI auth zone update delrr --zone "$ZONE" --via api \
  --rr "h7-vict-$RUN.$ZONE 300 IN A 10.15.0.1" >/dev/null 2>&1
[ -z "$(rr $PPORT h7-vict-$RUN.$ZONE a)" ] \
  && ok "setup: the victim is deleted in the live zone" || bad "setup: the victim is still served"

rm -f $R/zones/rig.example.*.rejected
append_norebump "h7-file-$RUN.$ZONE 300 IN A 10.15.0.2"
reload >/dev/null 2>&1

[ "$(rr $PPORT h7-file-$RUN.$ZONE a)" = "10.15.0.2" ] \
  && ok "the conflicting edit was loaded" || bad "the conflicting edit was not loaded"
[ -z "$(rr $PPORT h7-vict-$RUN.$ZONE a)" ] \
  && ok "db-wins on the RELOAD path: the file's record stays deleted" \
  || bad "the reload resurrected a record the journal deleted"
ARTH=$(ls $R/zones/rig.example.*.rejected 2>/dev/null | tail -1)
[ -n "$ARTH" ] && ok "the reload wrote a .rejected artefact ($(basename $ARTH))" \
  || bad "a conflict was resolved on reload with no artefact"
if [ -n "$ARTH" ] && grep -q "^ADD h7-vict-$RUN" "$ARTH" 2>/dev/null; then
  ok "the artefact names the record that lost"
else
  bad "the artefact does not carry the losing record"
fi

note "H8. a restart after all of this is a plain replay"
# The journal is re-anchored by every merge, so nothing above may leave the zone
# merging the same file forever, and a restart must not lose any of it.
NBH=$(ls $R/zones/rig.example.*.rejected 2>/dev/null | wc -l | tr -d ' ')
if restart_primary; then ok "primary restarted after the reload sections"
else bad "primary did not come back"; fi
NAH=$(ls $R/zones/rig.example.*.rejected 2>/dev/null | wc -l | tr -d ' ')
[ "$NAH" = "$NBH" ] && ok "no re-merge on the restart (artefacts still $NAH)" \
  || bad "the restart merged again: $NBH -> $NAH artefacts"
[ "$(rr $PPORT h5-$RUN.$ZONE a)" = "10.13.0.1" ] \
  && ok "the journalled change survived the restart" || bad "a journalled change was lost"
[ "$(rr $PPORT h6-file-$RUN.$ZONE a)" = "10.14.0.1" ] \
  && ok "the reloaded file content survived the restart" || bad "reloaded file content was lost"
echo "================================"
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" = "0" ] || exit 1
