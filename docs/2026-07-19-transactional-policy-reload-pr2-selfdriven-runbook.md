# PR-2 policy-reload — self-driven execution runbook (agent-run)

Companion to the matrix/spec doc
`2026-07-19-transactional-policy-reload-pr2-test-plan.md`. That doc says *what*
each scenario proves and *why*; this one is the **executable** version: who runs
it (this Claude Code session, driving foffe over SSH), the exact commands, the
machine-checkable assertions, and — critically — which steps I run autonomously
vs. which need Johan present. Scenario IDs (A1, B1, C1, …) refer to the matrix
doc.

## 0. Two corrections folded in (from the debug-policy-reload review)

Authoritative over the older "reload / restart" phrasing in the spec doc:

1. **The reload trigger is `reload-zones` (or `zone reload -z`), NOT `config
   reload`.** `config reload` → `ReloadConfig → ParseConfig(true)`, which never
   calls `ParseZones`, so the per-zone `syncZoneDnssecPolicyFromConfig` (the whole
   PR-2 surface) does not run. Only `reload-zones` (`ReloadZoneConfig → ParseZones`
   → `ConfigUpdate` refreshers) exercises it. Everywhere the matrix says "reload,"
   I drive `tdns-cli auth config reload-zones` (or `zone reload -z <z>`).
2. **RRSIG inception (S2) is NOT a valid signal at restart.** An online/inline
   signed zone is re-signed at every load (`RRSIG.Inception = time.Now()`), so a
   restart advances inception for *every* zone regardless of backfill. The restart
   rows (B2/C2/D3) are validated by **S1** (bound policy + `applied_*` via `zone
   desc`), **S3** (still SECURE / served), and **S5** (warning/error) — never by
   inception. S2 stays the workhorse only for the *reload-zones* rows (in-memory
   RRSIGs are retained across a reload).

## 1. Where this runs, and the build

Single environment: **foffe** (NetBSD, serves the ~135 PQ combo zones of
pq.axfr.net behind the hetz `:53` DNAT). nox drops out of the self-driven plan — I
have no confirmed path to it; foffe carries both the scale test (its full zone
set) and the focused matrix (on dedicated throwaway zones I provision). I reach
foffe over SSH (`ssh root@foffe`, likely ProxyJump via hetz — the lab is public
119/8 space, so reachable from the Bash sandbox where a pure RFC1918 host would
not be).

**The feature set is already assembled.** The two tools are merged to `main`
(#302 A2, #303 config-check) and forward-merged into the server branch #292
(`feature/transactional-policy-reload-pr2`, merge `6da9344`). So a single checkout
of **#292** builds the whole correct set: `tdns-auth` (the PR-2 server with the
backfill/sync under test), `tdns-cli` (with `config check`'s alg-vs-active-key
prediction), and `tdns-debug` (the redesigned A2 `test policy-reload`). Do **not**
build foffe from `main` — `main` lacks the PR-2 server, so it would test nothing.

## 2. Phase 0 — access & inventory (autonomous, read-only; run first)

Nothing here mutates foffe. It answers "can I drive this, and how."

- **Reach:** `ssh -o ConnectTimeout=8 root@hetz hostname`, then `ssh root@foffe
  'uname -sr; hostname'`. Confirm the (possibly ProxyJump-via-hetz) path works from
  this sandbox.
- **Inventory foffe** (drives every later decision):
  - `tdns-auth` install path + running version; how it's supervised (rc.d? a
    `nohup`/tmux?) — I must know how to stop/start it.
  - config file path, `include:` files, and the keystore DB path (`db.file`).
  - DNS listen address:port (for `dig @…` and `tdns-debug --dns`), and the
    mgmt-API endpoint + how `tdns-cli`/`tdns-debug` authenticate to it.
  - the served zone list + count (`tdns-cli auth zone list`); confirm on a sample
    (`zone desc`) that they are config-only, online-signed, `applied_*`-absent
    (the A2 precondition).
  - **Build/deploy path — the gating unknown:** does foffe have a Go toolchain +
    the PQ cgo libs (liboqs/…) to build tdns *in place*, or is the binary
    cross-compiled / built on hetz and copied? Discover how the *current* foffe
    binary got there and reuse that path. (`tdns-debug` is pure-client, CGO off —
    easy; `tdns-auth` with PQ algs is the hard one.)
- **Baseline snapshot for restore** (so any step is reversible): back up the
  binary, config, and keystore DB; dump `SELECT * FROM ZonePolicyOverride`; and
  capture a tdns-debug per-zone apex SOA+DNSKEY RRSIG inception snapshot over the
  full set.

## 3. Phase 1 — deploy the #292 build (GATED: Johan present)

The "software upgrade at foffe" — a real change to a live testbed. Never
unattended, and I cannot see approval prompts, so I will not claim it ran
unattended.

- Build, for foffe's platform via the Phase-0 path, `tdns-auth` + `tdns-cli` +
  `tdns-debug` from **#292**.
- Deploy: stop tdns-auth → back up current binary → install new → start →
  **verify clean startup** (all zones reach Ready, a sample stays SECURE on the
  wire). This startup is itself a data point (does the PR-2 binary come up on the
  real PQ set) — judged by S1/S3/S5, not inception (§0.2).
- Rollback: the backed-up binary + keystore; if it doesn't come up, restore and
  stop.

## 4. Phase 2 — fixtures I provision (autonomous, isolated from the live set)

The destructive matrix (B/C/D/E/G) must **not** touch the 135 live PQ combos. I
create a small set of dedicated throwaway signed zones on foffe (e.g.
`preload-{a,b,c}.<test-subdomain>`), each online-signed, plus the policy
definitions the matrix needs:
- two same-alg policies `polFOO`/`polBAR` (B, compatible rename),
- an incompatible-alg policy `polPQ` (KSK alg ≠ the zone's active-key alg, C),
- a deletable policy `polDROP` (D).
The live 135-set is reserved for **A2 only** (non-destructive: backfill records a
row, it must not re-sign).

## 5. Phase 3 — scenario runbook (each = commands + an assertion I check)

Signal capture reused everywhere:
- **S1** `applied_*` / bound policy: `tdns-cli auth zone desc -z <z>` → parse the
  `Applied policy:` and `DNSSEC detail:` lines.
- **S2** inception (reload rows only): `dig @<foffe> SOA <z> +dnssec` and `…
  DNSKEY +dnssec` → RRSIG inception per keytag, before vs after.
- **S3** validation: `dog @<foffe> <z> SOA --dnssec` / `delv` against the parent DS.
- **S5** state/warning: `tdns-cli auth zone list -v` / `zone desc` → `State:
  serving Warning[dnssec-policy-warning]` / `State: ERROR`; plus grep the foffe log
  for `backfilled…without re-sign` / `refused incompatible…` / `skipping config…
  ZSK roll in flight`.

Representative fully-scripted rows (the rest follow by matrix ID):

- **A2 — herd (full-set arming is GATED).** Arm `applied_*`→NULL over the set
  (`UPDATE ZonePolicyOverride SET applied_policy=NULL, applied_source=NULL,
  applied_at=NULL;`) → `tdns-debug test policy-reload --target <foffe> --dns
  <addr:53>` (it snapshots, drives **reload-zones**, re-snapshots, compares).
  **Assert:** report has zero `A2` violations, `applied.backfilled == N` (the
  coverage guard stays silent → the backfill path was actually exercised), no
  `A2-signed` drop. Spot-check a sample with `zone desc` → `applied=…,
  source=config`.
- **B1 — compatible rename (test zone, autonomous).** `zone desc` → applied=polFOO;
  capture SOA/DNSKEY inception; edit zone→polBAR (same algs); `config
  reload-zones`; re-capture. **Assert:** inception **advanced** (synchronous
  force-sign), `zone desc` applied=polBAR source=config, `dog` SECURE, AXFR sigs
  fresh.
- **C1 — incompatible refuse (test zone, autonomous).** applied=polFOO (e.g.
  ED25519); **pre-check with `auth config check`** — its new alg-vs-active-key
  correlation should WARN that reload would refuse (predict==actual cross-check);
  edit zone→polPQ; capture; `config reload-zones`. **Assert:** `zone desc` applied
  **unchanged**=polFOO; `dig` still SECURE under ED25519; inception **unchanged**;
  S5 log `refused incompatible…`. Then **C2 restart** (stop+start): the zone comes
  up **signed, not SERVFAIL** under polFOO (S3 SECURE, S1 applied=polFOO) — judged
  by S1/S3/S5, not inception.
- **D1 — deleted intent policy (test zone).** Delete polDROP from YAML; `config
  reload-zones`. **Assert:** S5 `Warning[dnssec-policy-warning]` "keeping bound
  policy"; `dog` still SECURE; process still up (no crash).
- **G2 — ConfigUpdate gate (test zone).** Plain refresh/NOTIFY (not config-bearing)
  → `zone desc` applied unchanged; then `zone reload -z` → sync runs. **Assert:**
  sync fires only on the config-bearing path.

Remaining rows (A1/A3/A4, C3, D2/D4, E1–E4, F1/F2, G1/G3/G4, H1/H2) follow the same
command/assert pattern by ID. E3 (DS break) and any full-set mutation are gated.

## 6. Autonomous vs. gated

- **Autonomous (I just run):** all of Phase 0; Phase 2 fixtures; every matrix row on
  the **dedicated test zones** (B/C/D/G/F, non-destructive to the live set);
  read-only baseline snapshots; `config check`.
- **Gated (Johan present, explicit go — never unattended, since I cannot see
  approval prompts):** Phase 1 deploy of the #292 binary; the A2 **full-set**
  `applied_*` arming + herd run (small blast radius if PR-2 is correct, a mass
  re-sign of 135 PQ zones if it isn't); **E3** (policy-reset that breaks the parent
  DS); anything that mutates the live PQ zones.

## 7. Verdict

I roll the per-row asserts up into the matrix doc's §6 merge gate: every A/B/C/D
row green on its listed signals, A2 herd clean, C2 comes up signed (not SERVFAIL),
no BOGUS outside the deliberate E3 DS-break. I report pass/fail per row with the
captured `zone desc`/`dig`/log evidence, not a bare "passed."

## 8. Open logistics to close in Phase 0

1. **foffe build/deploy path for PQ-cgo binaries** — the gating unknown for Phase 1.
2. **SSH reach** (direct vs ProxyJump-via-hetz) from this sandbox.
3. **A test subdomain** on foffe I may provision throwaway zones under (or Johan
   names one).
4. **`tdns-debug`/`tdns-cli` mgmt-API target** for foffe from wherever I drive them.
