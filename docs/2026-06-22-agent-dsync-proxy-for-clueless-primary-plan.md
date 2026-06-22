# tdns-agent as a DSYNC proxy for a DSYNC-unaware primary

Status: PLANNING (2026-06-22). Scope decisions resolved with the operator
(§4): NOTIFY-only first cut; a new `delegation-sync-proxy` zone option; a
WIDE change-detection trigger (CDS / CSYNC / NS+glue / DNSKEY) with an
optimistic act-mapping (CDS|DNSKEY change → NOTIFY(CDS), CSYNC|NS-glue
change → NOTIFY(CSYNC)); no special delete-DS handling; do not gate on
unsigned. UPDATE-to-parent is deferred to a later step. Ready to build. Estimate
(§9): ~150–280 source + ~330–520 test LOC, ~11–18 h for the NOTIFY-only
cut (P-1..P-4); no HIGH-risk step (a wrong NOTIFY only makes the parent
re-scan). The change-detection pattern is a proven tdns-mp template
(`MPPreRefresh`), and two of the three diff dimensions reuse existing v2
functions — so this is mostly trigger+gate glue, not new mechanism.

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

1. **A post-transfer trigger for the NON-MP agent-proxy case.** The
   `OnZonePreRefresh`/`OnZonePostRefresh` callback hooks
   (`structs.go:158-168`, fired in `FetchFromUpstream`,
   `zone_utils.go:248-285`) are a PROVEN pattern — tdns-mp already uses
   them exactly this way: `tdns-mp/v2/config.go:60-71` registers
   `MPPreRefresh`/`PostRefresh`, and `MPPreRefresh`
   (`tdns-mp/v2/hsync_utils.go:1257`) runs delegation + HSYNC + DNSKEY
   change-detection on old-vs-new and records it in a `ZoneRefreshAnalysis`
   struct, which `PostRefresh` then acts on. So "PreRefresh diff → analysis
   → PostRefresh act" is not speculative; it is the established template.
   What is MISSING is the analogous registration for the plain
   `agent + Secondary` NON-MP zone: the MP wiring is gated on
   `OptMultiProvider` and lives in tdns-mp, so the proxy needs its own
   (smaller) registration in the non-MP path. The reusable PARTS are
   already in `tdns/v2/`:
   - `DelegationDataChangedNG` (`delegation_utils.go:239`) — old-vs-new
     NS / A-glue / AAAA-glue / DS delta, returns a `DelegationSyncStatus`.
   - `DnskeysChangedNG` (`delegation_utils.go:462`) — old-vs-new DNSKEY
     change. (Both are `*ZoneData` methods, usable outside MP.)
   - The `ZoneRefreshAnalysis` struct (`structs.go:78-85`) — the carrier.
   Only the CDS/CSYNC RRset-change detection is genuinely new (a small
   `RRsetDiffer` over `dns.TypeCDS`/`dns.TypeCSYNC`).

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

- **Step P-1 — config: the `delegation-sync-proxy` option + gate.**
  STATUS: DONE. Added `OptDelSyncProxy` / `"delegation-sync-proxy"` to
  `enums.go` (within the tdns ZoneOption range; the compile-time sentinel
  gate still passes) and to the simple-enable case in `parseoptions.go`.
  Added a proxy gate block in `SetupZoneSync` (`zone_utils.go`) that
  validates the option is used only on a `tdns-agent + Secondary` zone
  (loud ConfigError otherwise) and logs it; no send behavior yet — the
  change-detection hook (P-2) and NOTIFY action (P-3) are wired
  separately. Tests (`delsync_proxy_test.go`): option string<->enum
  mapping both directions; `parseZoneOptions` enables it without a
  ConfigError. Build (all binaries incl. tdns-agent) + full
  `go test -race` green.

- **Step P-2 — wide change-detection hook (the trigger).** STATUS: DONE.
  Mirrored the tdns-mp template: `parseconfig.go` registers an
  `OnZonePreRefresh` + `OnZonePostRefresh` pair for `OptDelSyncProxy`
  zones. `delsync_proxy.go` adds `ProxyDelegationAnalysis` (the carrier;
  also stored on `ZoneData.ProxyRefreshAnalysis`, `structs.go`),
  `ProxyDelegationPreRefresh` (diffs old-vs-new: CDS/CSYNC via a small
  apex `core.RRsetDiffer`, NS+glue+DS via the existing
  `DelegationDataChangedNG`, DNSKEY via the existing `DnskeysChangedNG`),
  and `ProxyDelegationPostRefresh` (on any change, enqueues a
  `PROXY-NOTIFY` `DelegationSyncRequest` carrying the changed dimensions +
  the delegation deltas, and clears the analysis). The D4 act-mapping is
  encoded as `wantCDSNotify` (CDS|DNSKEY) / `wantCSYNCNotify`
  (CSYNC|NS-glue). The `PROXY-NOTIFY` command currently lands on the
  DelegationSyncher's safe `default` (warn+ignore) until P-3 adds the
  handler — so P-2 is working code on its own. Tests
  (`delsync_proxy_p2_test.go`): no-change → nothing; each of CDS / CSYNC /
  NS-glue / DNSKEY flips exactly its flag and the right
  want{CDS,CSYNC}Notify; PostRefresh enqueues exactly one PROXY-NOTIFY on
  change, nothing on empty/absent analysis, and clears the analysis. Build
  + full `go test -race` green.

- **Step P-3 — proxy NOTIFY action (the act).** STATUS: DONE. New
  `PROXY-NOTIFY` command in the `DelegationSyncher` switch
  (`delegation_sync.go`) calls `ProxyNotifyParent` (`delsync_proxy.go`):
  resolve parent if needed, `BestSyncScheme` for DSYNC discovery, require a
  NOTIFY target (NOTIFY-only, D3/D9 — UPDATE-only parent ⇒ logged no-op,
  not an error), then emit per the D4 act-mapping. The emission is factored
  into `emitProxyNotifies` (CSYNC-then-CDS) so the mapping → NOTIFY is
  unit-testable without the network. NO `PublishCsyncRR()` / sign and NO
  `AnalyseZoneDelegation` (§5, D1). The changed-dimension set is carried
  from PostRefresh to the handler via a new
  `DelegationSyncRequest.ProxyAnalysis` field. Tests
  (`delsync_proxy_p3_test.go`): all seven act-mapping combinations emit the
  exact NOTIFY set (CDS-only, CSYNC-only, DNSKEY→CDS, NS/glue→CSYNC, both,
  all-four, none); target + zone pass through unchanged. The
  DSYNC-discovery half of `ProxyNotifyParent` needs the network and is
  left for testbed validation. Build + full `go test -race` green.

- **Step P-4 — loop/debounce (D8) + tests + operator doc.** STATUS: DONE.
  Q6 RESOLVED with NO extra state: the trigger is content-edge-triggered
  (it diffs the served zone against the incoming one), so a change fires
  exactly ONCE — on the transfer where the content appears — and a later
  transfer carrying the SAME already-forwarded content does NOT re-fire,
  even with a bumped serial. So a slow parent gets no NOTIFY storm and no
  "last-proxied serial" marker is needed; the self-debounce falls out of
  P-2's design. Q5 (AXFR vs IXFR) is handled by construction: PreRefresh
  reads the post-flip served zone, identical for both. Test
  (`delsync_proxy_p4_test.go`): three sequential refreshes (serial-only
  bump → CDS change → same-CDS re-transfer) enqueue exactly ONE
  PROXY-NOTIFY. Operator guide written
  (`2026-06-22-agent-dsync-proxy-operator-guide.md`). The remaining
  matrix rows (delete-DS CDS, unsigned-zone, no-DSYNC-target) are covered
  by earlier unit tests + by construction: delete-DS is just another CDS
  change (D1, the proxy never reads CDS contents); an unsigned zone has no
  CDS/CSYNC/DNSKEY so the diff finds nothing (and the option is not
  refused, D5); a no-NOTIFY-target parent is the logged no-op in
  `ProxyNotifyParent` (P-3). Build + full `go test -race` green.

- **Step P-5 — UPDATE-proxy (DESIGNED 2026-06-22, ready to build).** Add
  the DNS-UPDATE-to-parent scheme alongside the NOTIFY proxy. Unlike NOTIFY,
  UPDATE carries the actual delegation records as payload, so it works for
  UNSIGNED zones too (the headline advantage) and lands the change in one
  round-trip without relying on the parent's scanner. Full design below
  (§10). Estimate: ~150–280 source + ~150–250 test LOC, ~8–14 h; the SIG(0)
  trust model and the replace-form question are now resolved, so the HIGH
  risk from the NOTIFY-cut estimate is reduced to MED.


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


## 9. Effort / risk / LOC estimate

Per-step, for me to implement (build + `go test -race` green; testbed
validation is operator-gated and not in these figures). LOC are net new
source / new test, excluding reuse.

| Step | What | Risk | Src LOC | Test LOC | Time |
|------|------|------|---------|----------|------|
| P-1 | `delegation-sync-proxy` option + gate | LOW | 20–40 | 30–50 | 1–2 h |
| P-2 | Wide PreRefresh diff hook + enqueue | MED | 60–110 | 100–160 | 4–6 h |
| P-3 | Proxy NOTIFY action (act-mapping) | MED | 50–90 | 80–130 | 3–5 h |
| P-4 | Debounce + test matrix + operator doc | LOW–MED | 20–40 | 120–180 | 3–5 h |
| **Total (P-1..P-4, NOTIFY-only)** | | | **~150–280** | **~330–520** | **~11–18 h** |
| P-5 | UPDATE-proxy (LATER, separate) | HIGH | 80–160 | 120–200 | 6–10 h |

Calibration: tdns-mp's `MPPreRefresh` (the proven template) is ~120 lines
covering three detection dimensions plus role dispatch; the proxy hook is
narrower (no role dispatch, two dimensions reused + one new), so P-2's new
code is mostly the CDS/CSYNC diff + the enqueue glue, not the detection
itself.

Risk notes:

- **P-2 is the load-bearing step (MED).** The risk is not the diff logic
  (reuses `DelegationDataChangedNG`/`DnskeysChangedNG`, adds a small
  CDS/CSYNC `RRsetDiffer`) but the LIFECYCLE: registering the hook only
  for the right zones (agent + Secondary + proxy option), making sure it
  fires on the secondary transfer path (`FetchFromUpstream`, confirmed),
  and the old-vs-new pointer discipline the MP code already documents
  (PreRefresh sees both; do not act before the hard flip). The MP template
  de-risks this substantially — it is a known-good pattern to mirror, not
  a green-field design.
- **P-3 is MED for a subtle reason:** "skip publish-and-sign" means the
  proxy must NOT reuse `SyncZoneDelegationViaNotify` verbatim (that path
  mints + signs a CSYNC). It needs a thin proxy variant that emits the
  NOTIFY directly to the parent's DSYNC target. Getting the "we are a
  forwarder, not the source of truth" boundary right is the care item; the
  wire send itself is reused.
- **P-1, P-4 are LOW.** Config plumbing and tests/docs.
- **No HIGH-risk step in the NOTIFY-only cut.** Unlike the KSK alg-roll
  plan (whose K-2 sat one branch from a bogus-zone path), nothing here can
  break a served zone: the worst failure mode of a wrong NOTIFY is a
  parent that re-scans and finds nothing to do. That bounds the blast
  radius and is why this is comfortable to build incrementally.
- **P-5 (UPDATE-proxy) is HIGH and deliberately out of this work** — the
  SIG(0)-trust model (parent authorizing the agent as updater for a child
  it does not own) is an unresolved design question, not just code.

Confidence: HIGH for P-1..P-4. The two facts the estimate rests on are
both now verified — the heavy machinery operates on transferred-in data
(§2), and the PreRefresh→analysis→act pattern is proven in tdns-mp (§3).
The main estimate risk is the debounce/loop-safety detail (Q6), which
could push P-4 up if the existing delegation-sync path has no reusable
"already-synced" marker and one must be added.


## 10. UPDATE-proxy design (P-5)

All open questions resolved with the operator on 2026-06-22.

### 10.1 Trust model (resolved)

The parent authorizes a DNS UPDATE by the SIG(0) key that signed it
(`ValidateUpdate`, `sig0_validate.go:21`). Its path-3 (`FindSig0KeyViaDNS`,
`sig0_validate.go:161`) trusts a key whose public KEY is **published in the
child zone** and resolvable via DNS — exactly how a DSYNC-native child is
trusted, with NO parent-side configuration.

DECISION U1 — the agent holds a SIG(0) keypair and signs proxied UPDATEs
with `SignerName = <child zone>`. The agent's public KEY is published at
the child apex (the parent then resolves+trusts it via path-3). The agent
effectively signs *as the child*, with a key the child zone vouches for.

DECISION U2 (bootstrap) — the agent generates the keypair on proxy setup
and EXPORTS the public KEY; the OPERATOR publishes that KEY record at the
DSYNC-unaware primary, once, exactly as they already add DS/CDS there. No
new bootstrap protocol; the agent uses the private half once it sees its
KEY in the transferred zone. (P-5 includes the keygen + export tooling,
DECISION U6.)

### 10.2 Form: replace, not delta (resolved)

DECISION U3 — proxied UPDATEs are REPLACE-form by DEFAULT (delete the
RRset, re-add the current authoritative members) rather than delta
(add/remove diff). Replace is idempotent and self-correcting: it does not
depend on the parent's current state matching our assumption, so it fixes
drift instead of risking duplicate-adds or missed-removes. The form is
OPERATOR-OVERRIDABLE via the existing `parent-update` auth option
(`delta|replace`), mirroring the tdns-auth child path — the proxy reads the
same option but DEFAULTS to replace (auth defaults to delta). NOTE — this
required un-gating `replace` at the config parser too: `parseAuthOptions`
previously rejected `parent-update: replace` (the other half of the stale
miekg/dns workaround); it now accepts both values.

PRECEDENT — the KSK rollover engine ALREADY pushes the child's DS RRset to
the parent in replace form, in production: `BuildChildWholeDSUpdate`
(`ksk_rollover_ds_push.go:38`) does `RemoveRRset` (DEL ANY DS) + `Insert`
(new DS), and it does NOT go through the disabled
`SyncZoneDelegationViaUpdate` mode-switch. So replace-form is the normal,
exercised parent-UPDATE shape on the fork — strong corroboration of U3/U4.
Two conventions to copy from it that `CreateChildReplaceUpdate` should
match: `Ttl: 0` on the ClassANY delete (not 3600), and `m.SetEdns0(1232,
true)` (EDNS0 + DO — matters for PQ-sized records). Open U-build choice:
reuse `CreateChildReplaceUpdate` (`childsync_utils.go:173`, NS+glue+DS) for
the whole payload after aligning those conventions, OR reuse the proven
`BuildChildWholeDSUpdate` for the DS dimension and `CreateChildReplaceUpdate`
only for NS+glue. Lean toward one builder for all three, aligned to the
KSK conventions.

NOTE — `SyncZoneDelegationViaUpdate` currently refuses replace mode with a
stale "replace mode is currently broken" guard. That bug was in upstream
miekg/dns, NOT tdns; the tdns fork fixes it (and the KSK path above already
relies on the fix), so the guard is obsolete. DECISION U4 — remove that
refusal and re-enable shared replace mode as part of P-5 (verify the
existing child UPDATE path still works before/after — it benefits too).

### 10.3 Scope: NS+glue AND DS (resolved)

DECISION U5 — the UPDATE-proxy reconciles the full delegation: NS, A/AAAA
glue, and DS. DS is derived from the child's apex DNSKEYs (signed zones;
`AnalyseZoneDelegation` already does this, `delegation_utils.go:126`).
NS+glue applies to all zones including UNSIGNED — which is the case NOTIFY
cannot serve and the main reason to build UPDATE-proxy.

### 10.4 Trigger: two phases (the operator's model)

Both phases are gated by §10.8: they only run once the precondition state
machine reports READY (parent advertises UPDATE AND the agent's KEY is
published at the apex). In the foreign-KEY or waiting-for-KEY states no
UPDATE is sent.

The expensive parent comparison is a STARTUP reconciliation, not a
per-transfer operation:

- STARTUP (once, on first load of a proxy zone): run the full parent-vs-
  child compare `AnalyseZoneDelegation` (one network round-trip to the
  parent). If out of sync, send a replace UPDATE. This catches drift that
  accumulated while the agent was down, and means a restart does NOT
  re-send unless there is a genuine difference.
- STEADY-STATE (every transfer after): the LOCAL old-vs-new compare
  `DelegationDataChangedNG` (the PreRefresh diff already built for the
  NOTIFY proxy, P-2 — no parent round-trip). If the child's own delegation
  data changed, send a replace UPDATE.

Both phases share ONE payload builder: the replace of the current
authoritative NS/glue/DS read from the freshly-transferred zone. The two
comparisons only decide WHETHER to send; the payload never depends on the
parent's state (that is the point of replace-form). So the parent
round-trip happens once at startup, never in steady state.

### 10.5 Scheme selection

`BestSyncScheme` (`childsync_utils.go:386`) already picks UPDATE vs NOTIFY
from the parent's advertised DSYNC RRset + local preference. UPDATE
advertised → this path; NOTIFY advertised → the existing NOTIFY proxy
(§5). A parent advertising both is the operator's preference choice, as for
the native child path.

### 10.6 Build sub-steps

- U-a: the precondition + KEY-bootstrap state machine (§10.8). STATUS:
  DONE (state machine + wiring). `delsync_proxy_update.go`:
  `ProxyUpdatePreconditionCheck` runs the §10.8 flow — UPDATE-support gate
  (`LookupDSYNCTarget` with `SchemeUpdate`), apex-KEY check, ours-vs-foreign
  match (`proxyHoldsPrivateKeyFor`), keygen on absence (`proxyEnsureSig0Key`
  via `Sig0KeyMgmt`, no publish — a secondary can't author the zone), and
  the KEY-RR + HSYNCPARAM-pubkey operator instruction
  (`proxyBootstrapInstruction`). New `DelegationSyncWarning` ErrorType
  surfaces the foreign/waiting states on `zone list` (resilient-config
  quarantine; never hard-fails). New exported `core.NewHsyncparamPubkeyFlag`.
  Wired off the refresh path via a `PROXY-UPDATE-SETUP` DelegationSyncher
  command enqueued from `SetupZoneSync`. Tests: keygen idempotency,
  ours-vs-foreign, apex-KEY read, instruction text, pubkey RR. The
  DSYNC-discovery gate itself is network — testbed-validated. The on-demand
  CLI (`proxy-key`) is U-a2 (needs a daemon API endpoint). Build + full
  `go test -race` green.
- U-b: remove the stale replace-mode refusal (U4). STATUS: DONE. The
  refusal in `SyncZoneDelegationViaUpdate` is replaced with the real
  replace implementation: `CreateChildReplaceUpdate` over the
  `DelegationSyncStatus.New{NS,A,AAAA,DS}` full-set fields (already
  populated by the delegation analysis). The default delta path is
  untouched, so the existing child UPDATE path is unchanged. Tests
  (`childsync_replace_test.go`): the replace UPDATE is well-formed
  (ClassANY deletes of NS/DS + ClassINET adds of the new members), and the
  unsigned case (no DS) replaces NS+glue only. Build + full `go test -race`
  green. (The actual replace UPDATE landing at a real parent is
  testbed-validated — it is the fork's miekg/dns fix that makes it work on
  the wire.)
- U-c: the startup reconcile pass. STATUS: DONE. `ProxyStartupReconcile`
  (`delsync_proxy_update.go`), called once on first load from the
  `PROXY-UPDATE-SETUP` handler: runs the §10.8 precondition and, if READY,
  does a one-time parent compare (`AnalyseZoneDelegation`) and a proxied
  UPDATE ONLY when out of sync — so downtime drift is fixed without
  re-sending on every restart (the sync check gates the send even though
  replace-form would be harmless to re-send). Steady-state changes after
  this go through the U-e PreRefresh diff (no parent round-trip). Test: the
  not-ready early return (network-free). The READY reconcile path is
  network/testbed-validated. Build + full `go test -race` green.
- U-d: the UPDATE action. STATUS: DONE. `ProxyUpdateParent`
  (`delsync_proxy_update.go`): re-checks the §10.8 precondition (sends only
  in READY), resolves the parent UPDATE target, builds the UPDATE in the
  configured form (`proxyUpdateMode` — REPLACE default, DELTA if
  `parent-update: delta`), signs with the agent's SIG(0) key as the child
  (`SignerName = child zone`), and sends via `SendUpdate`. Replace reads the
  current authoritative NS+glue+DS from the served zone
  (`proxyCurrentDelegationRRs`; DS from apex DNSKEY SEP keys, empty for an
  unsigned zone); delta uses `AnalyseZoneDelegation`. The config parser now
  accepts `parent-update: replace` (U3). Tests: mode default/override,
  authoritative-RR reader (signed + unsigned). The send itself is
  network/testbed-validated. NOT yet wired to a trigger — U-c (startup) and
  U-e (scheme dispatch) call it. Build + full `go test -race` green.
- U-e: scheme dispatch. STATUS: DONE. The PostRefresh hook now enqueues a
  single generic `PROXY-SYNC` request (was `PROXY-NOTIFY`); the
  DelegationSyncher handler calls `ProxyDelegationSync`
  (`delsync_proxy_update.go`), which picks the scheme via `BestSyncScheme`
  and routes to `ProxyUpdateParent` (UPDATE) or `ProxyNotifyParent`
  (NOTIFY). UPDATE is preferred when advertised (one round-trip, works
  unsigned); if the UPDATE precondition is not yet READY (KEY not published)
  it falls back to NOTIFY so the change is not dropped during bootstrap.
  Scheme discovery + send run in the syncher (off the refresh path). Tests
  updated for the command rename; the dispatch itself is network/testbed-
  validated. Build + full `go test -race` green.
- U-f: tests (signed + unsigned zones; startup-reconcile fires once;
  steady-state local-diff fires on change; replace payload correctness;
  no-resend-on-restart) + operator doc (the manual KEY-publication
  bootstrap step).

DECISION U6 — the keygen + export tooling is part of P-5, not a separate
prerequisite.

### 10.7 Open items for U-build time

- The agent's SIG(0) key is per-child (stored under the child zone name).
  Confirm the keystore cleanly holds a key for a zone the agent only
  secondaries (not authors) — it should, since the key is keyed by zone
  name, but verify against `GetSig0Keys`/`Sig0StateActive`.
- Until the operator publishes the agent's KEY at the primary, the parent
  cannot validate the UPDATE (path-3 fails). The proxy should detect "my
  KEY is not yet in the transferred zone" and hold off / warn, rather than
  send UPDATEs the parent will REFUSE. A clean precondition check.


### 10.8 The precondition + KEY-bootstrap state machine (resolved)

The UPDATE-proxy cannot just "sign and send." The parent only trusts an
UPDATE signed by a SIG(0) key published as a KEY RR at the child apex
(§10.1, path-3). Since the agent is a SECONDARY, it cannot publish that
KEY itself — the operator must add it at the DSYNC-unaware primary. So the
agent needs a small state machine to (a) decide whether UPDATE-proxy is
even relevant, (b) ensure it holds a usable key, and (c) tell the operator
exactly what to publish — without ever hard-failing the zone.

DECISION U7 — the resolved flow, evaluated on a proxy zone (on setup and on
each transfer):

1. GATE: does the parent advertise DSYNC **UPDATE**? (DSYNC discovery /
   `BestSyncScheme`.) If NOT, UPDATE-proxy is not applicable to this zone —
   do NOT generate a key, do NOT nag the operator about a KEY record. The
   NOTIFY proxy (P-3) may still apply if the parent advertises NOTIFY. This
   gate comes FIRST, before any KEY handling.

2. If UPDATE is advertised, inspect the apex KEY RRset:
   - **KEY present, and we hold the matching private key** (the keystore
     has it — `GetSig0Keys(child, Sig0StateActive)` non-empty and
     `VerifyPublishedKeyRRs` confirms the published KEY is ours): READY.
     Sign and send proxied UPDATEs.
   - **KEY present, but it is FOREIGN** (we do not hold the private key for
     the published KEY): we cannot proxy via UPDATE, and we MUST NOT mint a
     competing KEY. WARN (not error) — surface a per-zone status visible on
     `tdns-cli zone list`: "DSYNC UPDATE proxy not operable: a foreign KEY
     occupies the apex; NOTIFY proxy may still apply." Disable the UPDATE
     proxy for this zone; keep serving the zone normally.
   - **No KEY present**: GENERATE a SIG(0) keypair (reuse the keystore
     `Sig0KeyMgmt` generate path), store it under the child zone name, and
     INSTRUCT the operator to add TWO records at the primary apex (U10):
     the agent's **KEY RR**, AND an **HSYNCPARAM `pubkey`** flag. WARN
     status on `zone list`: "DSYNC UPDATE proxy waiting: publish the KEY +
     HSYNCPARAM pubkey at the primary." HOLD OFF on UPDATEs until the KEY
     appears in a transfer (sending before then just earns a REFUSED).

DECISION U10 — the no-KEY operator instruction is TWO records, not one, and
is emitted ONLY when the parent advertises DSYNC UPDATE (step 1 gate):
  1. the **KEY RR** — the agent's SIG(0) public key at the child apex (the
     record the parent's path-3 validation resolves);
  2. an **HSYNCPARAM record with the `pubkey` flag** — the standardized
     instruction to ALL zone providers to (re-)publish the KEY found at the
     apex. `HSYNCPARAM_PUBKEY` is a real flag (key code 4, `core/
     rr_hsyncparam.go:45`; `HasPubkey()` at `:387`). Without it the KEY
     sits only in the one primary's copy; with it every provider in the
     zone's HSYNC set republishes it, so the bootstrap works in the
     multi-provider world too — not just a single primary. (Sibling flag
     `HSYNCPARAM_PUBCDS` does the analogous job for CDS.)

DECISION U8 — error severity: NONE of the above hard-fails. The agent
starts; all zones, including this one, are served normally as a secondary.
The foreign-KEY and waiting-for-KEY conditions are WARNINGS surfaced as a
per-zone status on `tdns-cli zone list` (reuse the existing
`zd.SetError`/zone-status surface that `VerboseListZone` already renders,
`cli/zone_cmds.go:408`). This matches the project's resilient-config
quarantine model: the UPDATE-proxy FUNCTION is degraded, not the zone.

DECISION U9 — operator instruction surfacing (BOTH): (a) on generation, log
the ready-to-paste records (KEY RR + HSYNCPARAM pubkey, U10) at Warn AND
record them in the per-zone status so they persist (and re-emit while still
missing); (b) a CLI command (e.g. `... keystore dnssec proxy-key -z
<zone>`) that prints, on demand, the exact KEY RR + HSYNCPARAM pubkey to
publish plus the current state (update-unsupported / ready / foreign /
waiting). The CLI emits the records ONLY in the waiting state (parent
supports UPDATE, no KEY yet); in the update-unsupported state it says so
and emits nothing to publish.

Reuse map: `DelegationSyncSetup` / `Sig0KeyPreparation`
(`delegation_sync.go:192,265`) are the child-side precedent — they
generate a keypair AND publish the KEY into the zone. The proxy reuses the
KEYGEN + keystore half (`Sig0KeyMgmt` generate, `GetSig0Keys`,
`VerifyPublishedKeyRRs`) but REPLACES the "publish into the zone" half with
the operator-instruction surfacing, because a secondary cannot author the
zone. So U-a is a new `ProxySig0KeyPreparation`-style function modelled on
`Sig0KeyPreparation` minus the publish step, plus the §10.8 state machine.

Open U-build detail: where the per-zone "UPDATE-proxy state" is rendered —
the simplest is the existing zone-error/status field (one warning line);
if a distinct non-error "warning" severity is wanted on `zone list`,
that may need a small status-field addition. Decide at build time; the
error-field reuse works for a first cut.


