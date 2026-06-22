# tdns-agent as a DSYNC proxy for a DSYNC-unaware primary

Status: PLANNING (2026-06-22). Scope decisions resolved with the operator
(§4): NOTIFY-only first cut; a new `delegation-sync-proxy` zone option; a
WIDE change-detection trigger (CDS / CSYNC / NS+glue / DNSKEY) with an
optimistic act-mapping (CDS|DNSKEY change → NOTIFY(CDS), CSYNC|NS-glue
change → NOTIFY(CSYNC)); no special delete-DS handling; do not gate on
unsigned. UPDATE-to-parent is deferred to a later step. Ready to build.

## 1. The problem

A zone's primary is often a stock nameserver (BIND9, Knot, NSD) that knows
nothing about DSYNC — it cannot discover the parent's DSYNC RRset, and it
will never send a NOTIFY(CDS/CSYNC) or a DNS UPDATE to the parent to keep
the delegation in sync. But that primary CAN be configured (or scripted)
to PUBLISH a CDS/CDNSKEY RRset (RFC 7344) and/or a CSYNC RRset (RFC 7477)
in the zone, which is the standard, vendor-neutral way for a child to
SIGNAL "please sync my DS / my delegation."

The idea: run tdns-agent as a SECONDARY for that zone. The agent already
receives the full zone by AXFR/IXFR from the clueless primary. If the
transferred zone contains a CDS and/or CSYNC RRset, the agent can act as a
DSYNC PROXY: discover the parent's DSYNC receiver and forward the
appropriate NOTIFY(CDS/CSYNC) and/or DNS UPDATE to it on the primary's
behalf. The primary stays DSYNC-clueless; the agent does the DSYNC legwork.

This is the missing third leg. Today:

- PARENT side: complete. tdns-auth as a parent publishes a DSYNC RRset and
  receives both NOTIFY(CDS/CSYNC) and DNS UPDATE from children
  (`notifyresponder.go:195` dispatches CDS/CSYNC to the scanner;
  `scanner.go` runs `CheckCDS` / `ProcessCSYNCNotify` and applies changes).
- CHILD-PRIMARY side (tdns-auth as the primary): complete. On a local
  delegation/DNSKEY change it analyses, then sends NOTIFY(CDS/CSYNC) or
  UPDATE to the parent (`SyncZoneDelegationViaNotify` /
  `SyncZoneDelegationViaUpdate`, driven from `zone_updater.go` on local
  UPDATEs and from key bootstrap).
- CHILD-SECONDARY side (tdns-agent secondary for a clueless primary):
  MISSING. Nothing inspects an incoming transfer for CDS/CSYNC, and nothing
  triggers a parent-sync off a transfer. This plan closes that gap.


## 2. Key finding: the analyse + send machinery already works on xfr data

The most important discovery from the code survey is that the EXPENSIVE
parts are already built and already operate on transferred-in zone data —
NOT on a local keystore. So this is mostly a TRIGGER + GATE problem, not a
"build CDS/CSYNC forwarding from scratch" problem.

- `AnalyseZoneDelegation` (`delegation_utils.go:28`) computes the full
  parent-vs-child delta:
  - NS + A/AAAA glue: compares the child's apex/glue RRsets (from the
    SERVED zone data — i.e. what we transferred in) against what the parent
    publishes (`AuthQuery` to the parent servers). `delegation_utils.go:
    52-118`.
  - DS: derives the child DS from the apex DNSKEY SEP keys PRESENT IN THE
    ZONE (`apex.RRtypes...TypeDNSKEY ... dnskey.ToDS(SHA256)`,
    `delegation_utils.go:126-146`) and diffs against the parent's DS. It
    does NOT require a local keystore — a signed secondary zone carries its
    DNSKEYs, so this already yields the right DS for a clueless primary's
    zone.
  - Result is a `DelegationSyncStatus` with NsAdds/NsRemoves,
    A/AAAA adds/removes, DSAdds/DSRemoves.
- `SyncZoneDelegationViaNotify` (`delegation_sync.go:486`) takes that
  status and:
  - sends NOTIFY(CSYNC) iff any NS/glue delta, and NOTIFY(CDS) iff any DS
    delta (`delegation_sync.go:531-550`);
  - (for the notify path it currently also calls `PublishCsyncRR()` to mint
    a fresh CSYNC at the apex — see §5, this needs care for the proxy
    case).
- `SyncZoneDelegationViaUpdate` (sibling) sends the DNS UPDATE form.
- The `EXPLICIT-SYNC-DELEGATION` command (`delegation_sync.go:99`) already
  chains "analyse → if not in sync, sync via the parent's preferred
  scheme." That is almost exactly the proxy action; it just is never
  triggered for a secondary on transfer.

So for the DS / DNSKEY dimension and the NS/glue dimension, the agent does
NOT need to parse the incoming CDS/CSYNC contents to know WHAT to send —
`AnalyseZoneDelegation` already derives the correct delta from the zone
data + the parent. The incoming CDS/CSYNC is the OPT-IN SIGNAL ("the
primary wants parent-sync"), not the payload the agent must transcribe.

This reframes the CDS/CSYNC RRs: they are the primary's machine-readable
CONSENT to proxying, gating an action the existing analyse-and-sync engine
already knows how to perform.


## 3. What is actually missing

1. **A post-transfer trigger.** Nothing inspects a freshly transferred
   secondary zone, and nothing enqueues a delegation-sync off a transfer.
   The `OnZonePreRefresh`/`OnZonePostRefresh` callback hooks EXIST
   (`structs.go:158-168`, fired in `FetchFromUpstream`,
   `zone_utils.go:248-285`) but NOTHING registers a callback that looks at
   delegation/CDS/CSYNC. The `ZoneRefreshAnalysis` struct
   (`structs.go:78-85`, with `DelegationChanged`/`DnskeyChanged`) is
   defined but never populated. These unused hooks are the natural home.

2. **The change-detection trigger (WIDE — operator decision).** After a
   transfer, compare the new zone against the previously-served one and
   detect a change to ANY of: the CDS RRset, the CSYNC RRset, the NS RRset
   or its glue (A/AAAA), or the DNSKEY RRset. This is DELIBERATELY wider
   than "CDS/CSYNC present" (§4 D6): NS/glue and DNSKEY deltas feed the
   future UPDATE path's payload, and — per the act-mapping below — also
   drive NOTIFYs today. The read/diff primitives exist
   (`owner.RRtypes.Get(dns.TypeCDS/CSYNC/NS/DNSKEY)`, `core.RRsetDiffer`,
   and the old-vs-new zone pair the PreRefresh hook already receives).

3. **The config gate for the secondary-proxy role.** Today the child-side
   delegation-sync gate (`SetupZoneSync`, `zone_utils.go:858-860`) is:
   `OptDelSyncChild AND ((auth AND !MP) OR (agent AND MP))`. A tdns-agent
   that is a plain secondary for a clueless primary is `agent AND !MP` —
   which the current gate EXCLUDES. The proxy role is gated by a NEW,
   distinct option (§4 D2), not by loosening `delegation-sync-child`.

4. **Proxy semantics for the send path (do not mint a fresh CSYNC).** The
   notify path currently calls `PublishCsyncRR()` to publish a freshly
   minted CSYNC at OUR apex and sign it. As a PROXY for someone else's
   zone, we must NOT author/sign a new CSYNC into a zone we are only a
   secondary of — we forward the SIGNAL, we do not become the source of
   truth. The proxy send must skip the publish-and-sign step and just emit
   the NOTIFY (§5).


## 4. Resolved decisions (operator-confirmed 2026-06-22)

- **D1 — Reuse the existing send path; the proxy NEVER reads CDS/CSYNC
  contents.** A NOTIFY is a bare "come scan me" signal with no payload, so
  for the NOTIFY-only first cut the proxy never needs to interpret a CDS
  or CSYNC — it only detects that one CHANGED and emits the corresponding
  NOTIFY; the parent re-scans and reads whatever is there. This makes the
  RFC 8078 "delete DS" (`CDS 0 0 0 00`) case automatic: a changed CDS
  fires NOTIFY(CDS) regardless of whether it is a delete-DS sentinel or a
  normal CDS — the parent reads and acts (operator-confirmed: "doesn't
  matter if it is a CDS 0 0 0 00 or not").

- **D2 — NEW zone option `delegation-sync-proxy` (CHILD-side, agent
  secondary).** Distinct from `delegation-sync-child` ("I am the child,
  sync my own delegation up") because proxying for a clueless primary is a
  different role/consent statement. Explicit option beats inferring the
  role from `ZoneType==Secondary`. (Operator-confirmed.)

- **D3 — FIRST STEP IS NOTIFY-ONLY.** No DNS UPDATE to the parent in step
  one. The UPDATE-to-parent path is later work (§4 D5 notes why it is
  attractive). (Operator-confirmed Q1.)

- **D4 — Act mapping (operator-chosen, "be optimistic"):**
  - NOTIFY(CDS) is sent when the **CDS RRset changed OR the DNSKEY RRset
    changed**.
  - NOTIFY(CSYNC) is sent when the **CSYNC RRset changed OR the NS RRset
    and/or glue (A/AAAA) changed**.
  Rationale: a NOTIFY is cheap and harmless — it just tells the parent to
  re-scan; the parent decides for itself and ignores it if there is
  nothing to do or it offers no DSYNC service. So we forward the INTENT
  even when the primary changed keys/NS without (yet) republishing the
  CDS/CSYNC. Consequence: under D4 every dimension of the wide trigger
  drives a NOTIFY today, so the "detect-but-don't-act-yet" set is empty in
  step one — the NS/glue and DNSKEY deltas are still COMPUTED (they feed
  the future UPDATE payload) but they also fire their NOTIFY now.

- **D5 — Do NOT gate on "zone unsigned" in the trigger/gate.** CDS and
  CSYNC presuppose a signed zone, so in practice the NOTIFY-only cut only
  has something to forward for signed zones — but the GATE must not refuse
  unsigned zones, because the future DNS UPDATE path works for UNSIGNED
  zones too (its advantage over NOTIFY). Gating on "unsigned" now would
  wrongly foreclose that. (Operator-confirmed Q4.) So: no unsigned refusal;
  it simply happens that an unsigned zone has no CDS/CSYNC/DNSKEY to act on
  in the NOTIFY cut.

- **D6 — The trigger is WIDER than the act.** Detect changes to CDS /
  CSYNC / NS+glue / DNSKEY even though (per D4) all of them currently
  drive a NOTIFY. The point is that the change-DETECTION machinery (the
  old-vs-new delegation/DNSKEY diff) is built once, correctly, now — so the
  later UPDATE path has its payload deltas ready and does not need a second
  detection pass. (Operator-confirmed: "make the trigger wider … better
  positioned later for DNS UPDATEs.")

- **D7 — Gate on the conditions below before any send, every time:**
  (a) the `delegation-sync-proxy` option is set on the zone; AND
  (b) a relevant change was detected in this transfer (D4 dimensions); AND
  (c) the parent actually advertises a DSYNC RRset with a scheme/type we
      can use (`DsyncDiscovery` / `BestSyncScheme`, `childsync_utils.go:
      386`). No NOTIFY scheme advertised at the parent ⇒ do nothing (not an
      error; the parent may not offer the service).
  This mirrors the operator's stated IFF.

- **D8 — Idempotency / no loop: act on a detected change, but suppress a
  re-NOTIFY when nothing new is owed.** The trigger fires on a zone-content
  change (old-vs-new diff), which is already edge-triggered, so a plain
  SOA-refresh with no zone change sends nothing. Additionally, to avoid
  re-NOTIFYing across refreshes while the parent is slow to absorb,
  remember the last serial we proxied for and/or only NOTIFY when the
  relevant RRset's content (not just the SOA serial) actually changed since
  the last proxy. (See §6 Q6 — confirm the exact debounce; the wide trigger
  already removes the common "every refresh re-sends" case because it keys
  on RRset content, not serial.)

- **D9 — Scheme: NOTIFY only, for now.** Use the DSYNC NOTIFY target the
  parent advertises (filtered via `DsyncDiscovery` / the CSYNC-and-CDS-
  capable scheme picker). UPDATE is explicitly NOT used in step one (D3).
  When UPDATE-proxy lands later, `BestSyncScheme` (`childsync_utils.go:
  386`) picks UPDATE vs NOTIFY per the parent's advertisement + local
  preference, as the primary-child path already does.


## 5. The proxy send: what differs from the primary-child send

The primary-child notify path (`SyncZoneDelegationViaNotify`) does, in
order: publish a fresh CSYNC at our apex → sign it → send NOTIFY. For the
proxy we change the first two steps:

- **Do NOT `PublishCsyncRR()` and do NOT sign.** We are a secondary; the
  CSYNC/CDS already exists in the zone (the primary put it there) and is
  already signed by the primary's keys (if the zone is signed). We forward
  the SIGNAL. Authoring a second CSYNC into a zone we don't own is wrong
  and, for a signed secondary without the primary's ZSK, impossible to
  sign correctly anyway.
- **The NOTIFY is a bare signal.** A NOTIFY(CDS) / NOTIFY(CSYNC) carries no
  payload — it just tells the parent "come scan my child." The parent then
  queries the child (via its configured scanner) and reads the CDS/CSYNC
  ITSELF. So for the NOTIFY scheme the proxy literally only needs to emit
  the NOTIFY to the parent's advertised target; the parent's existing
  `CheckCDS`/`ProcessCSYNCNotify` does the rest by querying the zone (which
  it can reach — the agent serves it, or the primary does). This makes the
  NOTIFY proxy path very small.
- **No `AnalyseZoneDelegation` needed for the NOTIFY decision (D1).**
  Because a NOTIFY is contentless and the parent re-scans, the proxy does
  NOT need the parent-vs-child delta to decide whether to NOTIFY — the
  local old-vs-new change-detection (D6) is sufficient: "this RRset changed
  ⇒ NOTIFY." (We still keep the delta computation around per D6 to
  pre-position the UPDATE path, but it does not gate the NOTIFY.) This
  removes a parent round-trip (`AuthQuery` to the parent servers) from the
  hot path; the only parent contact in step one is DSYNC discovery + the
  NOTIFY send itself.

The future UPDATE-proxy step (NOT step one) carries payload and reuses
`AnalyseZoneDelegation`'s delta + `SyncZoneDelegationViaUpdate`'s signed-
UPDATE builder, and brings a SIG(0)-trust question (the parent must accept
the agent's key as the authorized updater for a child the agent does not
own). That is deferred; see §6 Q-UPDATE.


## 6. Sharp edges (most resolved 2026-06-22; two confirmations left)

RESOLVED by operator (recorded in §4): delete-DS needs no special handling
(D1 — a changed CDS NOTIFYs regardless of sentinel); NOTIFY-only first
(D3); the act mapping is the optimistic CDS|DNSKEY→NOTIFY(CDS) /
CSYNC|NS-glue→NOTIFY(CSYNC) (D4); do not gate on unsigned (D5); the trigger
is wide (D6); a new `delegation-sync-proxy` option (D2). CDS and CSYNC are
evaluated independently and can both fire (falls out of D4).

Remaining to confirm during build:

- **Q5 — IXFR (delta) transfers.** On an IXFR we get a delta; the
  post-refresh hook sees the new full zone regardless (the hard flip
  rebuilds `zd.Data`), so reading the apex CDS/CSYNC post-flip works for
  both AXFR and IXFR. Confirm — but it should be fine since we read the
  post-flip served zone, not the wire delta.

- **Q6 — Rate / loop safety.** A parent that is slow to absorb the change
  will leave the zone "not in sync" across refreshes, so every SOA refresh
  would re-send. Reuse whatever debounce the primary-child path uses (or
  add a "last proxied serial / last sync attempt" marker) so we don't
  NOTIFY the parent on every refresh tick. Check what the existing path
  does to avoid re-sending; the rollover path has `last_success_at` style
  state — the delegation-sync path may need an analog.


## 7. Build order

Scope is settled (§4). Per the project rules: gofmt after edits; build
with `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`; show diff + update
this doc's step status before committing each step; verify by build +
`go test -race` (no testbed in the loop — but the agent-as-DSYNC-proxy is
exactly the kind of thing that wants a testbed run against a BIND/Knot
primary once it builds).

- **Step P-1 — config: the `delegation-sync-proxy` option + gate.** Add
  the option to `enums.go` (`AuthOption`/`ZoneOption` per the existing
  delsync options) + `parseoptions.go`. Extend the child-side gate in
  `SetupZoneSync` (`zone_utils.go:858`) so an `agent AND Secondary AND
  delegation-sync-proxy` zone is admitted (today it is excluded), without
  changing the existing `delegation-sync-child` behavior. No send behavior
  yet. Verify: option parses; the proxy case is admitted; a plain agent
  secondary (no proxy option) is still excluded.

- **Step P-2 — wide change-detection hook (the trigger).** Register an
  `OnZonePreRefresh` callback for proxy zones (PreRefresh, because it
  receives BOTH old `zd` and incoming `new_zd` — the diff needs both,
  `zone_utils.go:248`). It compares old-vs-new for the four dimensions
  (CDS, CSYNC, NS+glue, DNSKEY, via `core.RRsetDiffer`), records the
  result in `ZoneRefreshAnalysis` (`structs.go:78`, currently unused), and
  — when any dimension changed — enqueues a proxy-sync request carrying
  WHICH dimensions changed. Verify (unit tests): a transfer that changes
  CDS / CSYNC / NS / glue / DNSKEY each sets the right analysis flags and
  enqueues; an unchanged transfer (same content, new serial only) enqueues
  nothing (D8 edge-trigger).

- **Step P-3 — proxy NOTIFY action (the act).** A delegation-sync command
  (new `PROXY-NOTIFY`, or a proxy flag on the existing path) that, gated on
  D7 (proxy option set; a change was detected; parent advertises a NOTIFY
  DSYNC target), sends — per the D4 act mapping — NOTIFY(CDS) when CDS or
  DNSKEY changed, and NOTIFY(CSYNC) when CSYNC or NS/glue changed. It does
  NOT call `PublishCsyncRR()` / sign and does NOT need `AnalyseZoneDelegation`
  (§5, D1): a NOTIFY is a contentless "come re-scan" and the parent reads
  the zone itself. Verify: each act-mapping case emits the right NOTIFY(s);
  no DSYNC-NOTIFY target ⇒ no send, no error; both CDS+CSYNC changing fires
  both, independently.

- **Step P-4 — loop/debounce (D8) + tests + operator doc.** Confirm Q5
  (IXFR reads the post-flip served zone, so AXFR/IXFR behave identically)
  and settle Q6 (a "last-proxied content/serial" guard so a parent that is
  slow to absorb does not get re-NOTIFYd every refresh — though the
  content-diff trigger already suppresses the common case). Full test
  matrix: CDS-only, CSYNC-only, both, DNSKEY-only→NOTIFY(CDS),
  NS/glue-only→NOTIFY(CSYNC), delete-DS CDS (must NOTIFY like any CDS
  change), no-change no-op, no-DSYNC-at-parent no-op, AXFR vs IXFR,
  unsigned zone (no CDS/CSYNC/DNSKEY ⇒ nothing to send, but NOT refused —
  D5). Operator doc: configuring tdns-agent as a DSYNC proxy secondary for
  a BIND/Knot primary.

- **Step P-5 (LATER, not this work) — UPDATE-proxy.** Add the DNS-UPDATE-
  to-parent scheme: reuse `AnalyseZoneDelegation`'s delta +
  `SyncZoneDelegationViaUpdate`. Brings the SIG(0)-trust question (parent
  must authorize the agent's key as updater for a child it does not own)
  and the advantage of working for UNSIGNED zones (D5). Designed later;
  D5/D6 pre-position the change-detection so this step does not redo it.


## 8. Why this is small (NOTIFY-only first cut)

The parent side is done (receive + scan + apply). DSYNC discovery is done.
NOTIFY emission is done. And critically (§5, D1) the NOTIFY decision needs
NEITHER the publish-and-sign step NOR the parent-vs-child `AnalyseZone
Delegation` round-trip — a changed RRset simply NOTIFYs and the parent
re-scans. So the genuinely new code is:

1. one config option + a one-line gate change (P-1);
2. a PreRefresh callback that diffs four RRsets old-vs-new and enqueues on
   change (P-2) — the only real new logic, and it is reused wholesale by
   the future UPDATE path;
3. a proxy NOTIFY action that maps changed-dimension → NOTIFY type and
   emits to the parent's advertised target, skipping publish-and-sign (P-3).

Everything heavy (DSYNC discovery, NOTIFY wire send, parent-side
scan-and-apply, the RRset-differ) is reused. The part with the real open
question — SIG(0) trust for UPDATE-proxy — is explicitly deferred to P-5,
which is why NOTIFY-only is the first cut.
