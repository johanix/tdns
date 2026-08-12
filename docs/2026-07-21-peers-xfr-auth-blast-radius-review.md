# Adversarial re-review: XoT stack (#314 / #316 / #318) — blast-radius focus

**Date:** 2026-07-21 (evening)
**Worktree:** `tdns-peers` @ `feature/peers-xfr-auth` (stack tip)
**Lens:** mergeability by **risk to the rest of tdns** (ordinary queries, Do53
transfers, IMR recursion, sibling modules). XoT-only transfer bugs are
downgraded unless they also leak into shared paths.
**Prior review:** `docs/2026-07-21-peers-xfr-auth-adversarial-review.md`
(findings F1–F7). Fix commit: `1b1c2dc`.

---

## Verdict

**Close, but not mergeable yet** for a conservative “rest of tdns” bar.

- Prior config/wiring fail-opens (F1–F7) are fixed and regression-tested
  (`v2/review_regressions_test.go`).
- Shared **query** paths (Do53, cert-less ADoT, TSIG wrapper, empty
  `downstream-auth` AXFR semantics) look sound.
- Two **cross-subsystem** issues remain before merge:
  1. **`VerifyCertAgainstTlsaRR` API break → `tdns-mp` does not compile**
     against this module tip (live caller).
  2. **`AddStub` now overwrites shared `AuthServerMap` state** (addresses /
     transports), which can skew **IMR recursion** for non-XoT queries when
     stubs share an NS name with discovery or another stub.

Catch up `main` (~40 commits behind) before landing either way.

---

## Prior findings (F1–F7)

All addressed in `1b1c2dc` and guarded by `TestReview_*`. Not re-litigated.

---

## Confirmed blast-radius findings (this pass)

### 1. `VerifyCertAgainstTlsaRR` signature change breaks `tdns-mp` — **sibling-module break**

- **Where (this branch):** `v2/ops_tlsa.go` —
  `VerifyCertAgainstTlsaRR(tlsa, *x509.Certificate)` (was `[]byte`).
- **Where (consumer):** `tdns-mp/v2/apirouter_sync.go:99` still calls
  `tdns.VerifyCertAgainstTlsaRR(tlsaRR, clientCert.Raw)`.
- **Defect:** Phase 0 of the XoT plan assumed the only caller was dead
  commented code in `apiclient.go`. That was wrong: **tdns-mp’s API TLS gate
  is a live caller**. Bumping tdns-mp’s `github.com/johanix/tdns/v2` to a
  revision that includes this stack is a **compile failure**, i.e. it takes
  down multi-provider API auth until mp is patched.
- **Scenario:** Land #314+#316+#318 on `main` → cut a module version → mp CI /
  local `go build` fails on type mismatch (`[]byte` vs `*x509.Certificate`).
- **Severity:** blast-radius / merge coordination blocker (not an auth-daemon
  query bug, but it is “other parts of the tdns system”).
- **Fix:** land a one-line mp follow-up in the same window
  (`VerifyCertAgainstTlsaRR(tlsaRR, clientCert)`), or temporarily provide a
  thin wrapper (project usually prefers no dual API — prefer the mp patch).

### 2. `AddStub` overwrites shared nameserver state — **IMR recursion risk**

- **Where:** `v2/cache/rrset_cache.go:384-458` (`9fa7c97`).
- **Defect:** To make stub TLSA visible to `LookupTLSAForServer`, `AddStub`
  switched from a **private** `NewAuthServer` to
  `GetOrCreateAuthServer` (shared `AuthServerMap`), which is correct for
  identity. But it still **`SetAddrs` / `SetTransports` / `ForceSetSrc("stub")`**
  on that shared object. Contrast `AddServers` (discovery), which **merges**
  via `AddAddr` / `AddTransport` / `MergeTransportWeights` and does not clobber
  peer glue.
- **Scenario:**
  1. IMR discovers `ns1.example.` with glue `{192.0.2.10, 192.0.2.11}`.
  2. Config loads a stub that also names `ns1.example.` with `{203.0.113.1}`.
  3. `AddStub` replaces addrs/transports on the **global** instance.
  4. Later iterative queries that reuse `ns1.example.` (any zone) dial the
     stub address / transports — wrong upstream for ordinary recursion,
     independent of XoT.
- **Severity:** medium blast-radius for **IMR deployments that use stubs**;
  near-zero for auth-only primaries with no `imrengine.stubs`. Still in scope
  for “rest of tdns” because auth/agent can run an IMR for DANE / parent sync.
- **Fix:** register into `AuthServerMap` (keep), but apply stub config with
  **merge semantics** like `AddServers` (or isolate stub-only fields without
  `SetAddrs` clobber). Add a regression: discover then stub same NS name →
  glue addrs still present.

---

## Shared paths checked and believed sound (blast-radius)

| Path | Assessment |
|---|---|
| **Ordinary Do53 queries** | Untouched aside from `ServerErrors` bookkeeping on listen failure. |
| **Cert-less ADoT queries** | Auth DoT uses `tls.RequestClientCert` (request, not require); IMR DoT still passes `requestClientCert=false`. Ladder only runs in `ZoneTransferOut`. Covered by `TestDownstreamAuth_MUSTs`. |
| **Empty `downstream-auth` AXFR** | `authorizeTransfer` empty-list branch preserves pre-ladder ACL+TSIG semantics (BLOCKED, NOKEY, dual-key). Existing Do53 transfers with unchanged YAML should behave as on main. |
| **`tsigSignResponseWriter.Unwrap`** | Additive; `WriteMsg` / TSIG MAC path unchanged. |
| **`queryresponder` one-liner** | Passes `imr` only into apex AXFR/IXFR. |
| **Pre-XoT configs** | No `peers:` / no `downstream-auth` → `ValidatePeers` no-op; `expandPeerRefs` leaves inline lists alone; alias pass only rewrites alias keys. |
| **Secondary refresh without `transport: dot`** | `ClientTLSConfigForPeer` returns `(nil,nil)` → Do53 SOA/AXFR as before. |
| **dog** | Separate binary; no library import into auth/agent. |

---

## Residual XoT-only / lower-priority (not merge blockers under this lens)

- Transfer auth ladder edge cases, pin/DANE verify, PKI tooling — previously
  reviewed; runtime looked sound; residual risk stays inside AXFR/XoT.
- `PublishTlsaRR` now emits true 3-1-1 (SPKI). Correctness fix; anyone who
  published under the old (mis-hashed) generator may need to re-publish.
  Affects TLSA consumers, not query answering.
- Branch is ~40 commits behind `main`; re-merge before land (merge-tree
  already shows overlapping files).

---

## Merge recommendation

1. **Patch `tdns-mp`** for `VerifyCertAgainstTlsaRR(*x509.Certificate)` (or
   land that patch in the same merge train as #314).
2. **Harden `AddStub`** so shared registration does not `SetAddrs`-clobber
   discovered state (merge like `AddServers` + test).
3. Re-merge `main`, open/refresh the PR(s), then merge.

After (1)+(2): **mergeable** from a blast-radius POV for typical auth Do53 /
ADoT service. Remaining risk is concentrated on opt-in XoT / `downstream-auth`
/ IMR-stub deployments, which is the acceptable shape for this stack.
