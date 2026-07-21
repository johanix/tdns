# PR #257 ← main: test-merge conflict analysis

**Date:** 2026-07-06
**Author:** merge dry-run performed in an isolated scratch worktree
**Status:** executed — see the update note below

> **Update:** The recommended path (Option A, [§7](#7-recommended-path-forward))
> was carried out: `origin/main` was merged into the new branch
> `imr-transport-selection-phase2` as GPG-signed merge commit `e9756ca`, and
> this document is committed alongside it. The scratch worktree referenced in
> §1 and §9 was a throwaway used only to produce this analysis and has since
> been removed. The per-conflict analysis below is preserved verbatim as the
> record of how the merge was resolved.

## TL;DR

I did a **non-destructive test merge of `origin/main` into a throwaway copy of
the PR #257 branch** (`imr-transport-selection-wip`). Despite main having moved
**209 commits** ahead, the merge produced only **3 conflicted files / 4 conflict
hunks**, and every one sits in the same small cluster: the DNSSEC-config
structs, their parser, and the IMR sample YAML.

I resolved all four hunks (union of struct fields, with one deletion), and the
result **`go build ./...` and `go vet ./...` clean** in the `v2` module.

**Verdict: LOW complexity, essentially mechanical.** There is exactly *one*
judgment call (a representation change for `large_algorithms`, codepoints →
names), and main's side is clearly the right one. #257's transport-selection
feature survives fully intact.

**Recommended path:** merge `origin/main` into `imr-transport-selection-wip`
(a real merge commit, GPG-signed, no rebase, no history rewrite), then push and
let PR #257 update. Details in [§7](#7-recommended-path-forward).

---

## 1. Setup (how this was produced, and why it is safe)

Nothing in this exercise touched `main`, `imr-transport-selection-wip`, or any
existing worktree. All work happened on a fresh scratch branch in a separate
worktree:

```
git fetch origin
git worktree add -b scratch/test-merge-main-into-257 \
    /Users/johani/src/git/tdns-project/tdns-257-mergetest \
    origin/imr-transport-selection-wip
cd /Users/johani/src/git/tdns-project/tdns-257-mergetest
git merge --no-ff --no-commit origin/main
```

The scratch worktree is still in place (with the resolution applied) if you want
to poke at it or build it yourself. To discard it completely:

```
git worktree remove --force /Users/johani/src/git/tdns-project/tdns-257-mergetest
git branch -D scratch/test-merge-main-into-257
```

| Ref | SHA | Note |
|-----|-----|------|
| `origin/main` | `651571c` | merge target |
| `origin/imr-transport-selection-wip` (#257) | `8c91063` | the branch we merge *into* |
| merge-base | `2d501b5` | "Merge pull request #256", **2026-06-11** |

## 2. Divergence

```
git rev-list --left-right --count origin/main...origin/imr-transport-selection-wip
209   2
```

- **main is 209 commits ahead** of the merge-base (≈4 weeks of heavy work:
  first-class TSIG keystore, dynamic zones, KSK/ZSK algorithm rollover, agent
  DSYNC proxy, the algorithm-registry name-based refactor, a large `reference/`
  CLI doc dump, etc.).
- **#257 is only 2 commits ahead**:
  - `313b3ea` imr: DNSKEY transport policy enum + transport-selection design
  - `8c91063` imr: address CodeRabbit review on PR #257

This asymmetry is the whole reason the merge is cheap: 209 incoming commits, but
#257's *own* footprint is tiny and touches main's changes in only one area.

## 3. Why so few conflicts

#257 changed just **11 files**:

```
cmdv2/cli/algorithms.measured-netbsd-x86.example.yaml   (new, additive)
cmdv2/imr/tdns-imr.sample.yaml                           ← CONFLICT
docs/2026-06-12-transport-selection-policy.md            (new, additive)
v2/cli/imr_stats_large_ksk.go                            (auto-merged)
v2/config.go                                             ← CONFLICT
v2/dnslookup.go                                          (auto-merged)
v2/imr_large_ksk_metrics.go                              (auto-merged)
v2/imrengine.go                                          (auto-merged)
v2/large_ksk.go                                          (auto-merged)
v2/large_ksk_test.go                                     (auto-merged)
v2/parseconfig.go                                        ← CONFLICT
```

Everything auto-merged except the three files where #257 and main **edited the
same DNSSEC-config lines**. Crucially, the sensitive IMR runtime files
(`imrengine.go`, `dnslookup.go`, `imr_large_ksk_metrics.go`, `large_ksk.go`)
auto-merged without textual conflict, and — see §6 — without a hidden semantic
break either.

## 4. The four conflicts, one by one

### 4.1 `v2/config.go` — `DnssecConf` struct (hunk 1)

**The tension.** Both sides extended the raw `DnssecConf` struct:

- **#257 (ours)** added `DNSKEYTransport string` and kept
  `LargeAlgorithms []uint8` (algorithm **codepoints**).
- **main (theirs)** changed `LargeAlgorithms` to **`[]string`** (algorithm
  **names**) and added four unrelated fields: `SplitAlgorithms`, `Templates`,
  `Policies`, `Kasp`, `Completeness`.

**Resolution: union of fields, drop #257's `LargeAlgorithms []uint8`.** Keep
main's full field set (including `LargeAlgorithms []string`) and add #257's
`DNSKEYTransport string`. Final resolved fields:

```go
DNSKEYTransport string                      `yaml:"dnskey_query_transport" ...`  // from #257
LargeAlgorithms []string                    `yaml:"large_algorithms" ...`        // main's type wins
SplitAlgorithms map[string][]string         `yaml:"split_algorithms" ...`        // from main
Templates       map[string]DnssecPolicyConf `yaml:"templates" ...`               // from main
Policies        map[string]DnssecPolicyConf `yaml:"policies" ...`                // from main
Kasp            KaspConf                     `yaml:"kasp" ...`                    // from main
Completeness    string                       `yaml:"completeness" ...`            // from main
```

**This is the one real decision in the whole merge.** main deliberately moved
`large_algorithms` from codepoints to names because non-standardized PQ
codepoints are assigned per-deployment at runtime by `algorithms.Register`, so a
bare codepoint could mean different algorithms on the IMR vs. the signer. That
reasoning is sound and supersedes #257's codepoint list. Adopting it costs #257
nothing at runtime (see §6). **Complexity: trivial once the decision is made.**

### 4.2 `v2/config.go` — `InternalConf` struct (hunk 2)

**The tension.** Both sides added *derived* fields next to the shared
`LargeAlgorithms map[uint8]bool`:

- **#257** added `DNSKEYTransport DNSKEYTransportPolicy` (validated policy).
- **main** added `SplitAlgorithms map[uint8]map[uint8]bool` and
  `Completeness string`.

**Resolution: pure union** — keep all three. No semantic overlap.
**Complexity: trivial.**

Note the shared line `LargeAlgorithms map[uint8]bool` is *outside* the conflict:
the internal, codepoint-keyed derived set is identical on both sides. That is
the key to why 4.1 is painless — see §6.

### 4.3 `v2/parseconfig.go` — decode preamble (hunk 1)

**The tension.** Pure adjacency. #257 inserted a "reset raw field before decode"
block (`conf.Dnssec.DNSKEYTransport = ""`, so a reload after the operator
removes the YAML key reverts to the default); main rewrote the immediately
following comment about the bare-string primary/notify decode hook.

**Resolution: pure union** — keep #257's reset line and main's fuller comment.
No logic overlap. **Complexity: trivial.**

### 4.4 `cmdv2/imr/tdns-imr.sample.yaml` (hunk 1)

**The tension.** The same two changes as 4.1, in doc/sample form:

- **#257**: `large_algorithms: [ 10 ]` (codepoint) + a new
  `dnskey_query_transport: use_ds_signal` line and its explanatory comment.
- **main**: `large_algorithms: [ RSASHA512 ]` (name).

**Resolution:** adopt main's **name** form and keep #257's new
`dnskey_query_transport` line; merge the two comment blocks. Final:

```yaml
dnssec:
   large_algorithms: [ RSASHA512 ]
   dnskey_query_transport: use_ds_signal
```

**Complexity: trivial**, but it *must* track the 4.1 decision (name, not
codepoint) or the sample would no longer parse. It now does.

## 5. What the resolution looks like in aggregate

| File | Hunks | Resolution | Complexity |
|------|-------|-----------|-----------|
| `v2/config.go` | 2 | union of fields; drop #257 `[]uint8`, keep main `[]string` | trivial (1 decision) |
| `v2/parseconfig.go` | 1 | pure union | trivial |
| `cmdv2/imr/tdns-imr.sample.yaml` | 1 | name form + keep new field, merged comments | trivial |

No algorithmic logic had to be reconciled by hand. No control flow changed. The
work is "keep both sets of struct fields, and accept that main renamed one
field's element type."

## 6. Semantic (non-textual) risk check — the important part

A clean textual merge can still hide a **compile or behavior break**, because
git merges *lines*, not *meaning*. The obvious candidate here: #257 was written
against `large_algorithms` as **codepoints (`[]uint8`)**, and main changed the
representation to **names (`[]string`)**. If #257's downstream code still assumed
codepoints, we'd get a silent break that no conflict marker would show.

I checked it explicitly, and it is fine, because the codepoint/name split lands
on a clean seam:

- **Raw config** `Dnssec.LargeAlgorithms` is `[]string` (names) — consumed in
  exactly one place, at parse time.
- **The bridge**: `buildLargeAlgorithmSet(names []string) (map[uint8]bool, error)`
  (`v2/large_ksk.go:31`, main's version) converts names → codepoint set via the
  registry. It lives in `large_ksk.go`, a file **#257 also edited**, and the two
  sets of edits auto-merged consistently.
- **Derived internal** `Internal.LargeAlgorithms map[uint8]bool` (codepoint-keyed)
  is **unchanged on both sides**.
- **The IMR runtime** — the sensitive part — reads only the derived codepoint
  set: `imrengine.go:66` (`imr.largeAlgs[alg]`), `imrengine.go:167`
  (`largeAlgs: conf.Internal.LargeAlgorithms`), `large_ksk.go:82`. It never sees
  a name. So #257's transport-selection logic is representation-agnostic and
  needs **zero changes**.

I also confirmed #257's **derivation wiring survived** the auto-merge (otherwise
an operator's `dnskey_query_transport:` value would be silently ignored):

```
v2/parseconfig.go:336   dnskeyXport, err := parseDNSKEYTransportPolicy(conf.Dnssec.DNSKEYTransport)
v2/parseconfig.go:340   conf.Internal.DNSKEYTransport = dnskeyXport
```

This now sits neatly *after* main's new `conf.parseDnssecConfig()` call.

### Build / vet evidence

In `/Users/johani/src/git/tdns-project/tdns-257-mergetest/v2`, with
`GOROOT=/opt/local/lib/go`:

```
go build ./...   → exit 0 (no output)
go vet ./...     → clean (no output)
```

`go vet` type-checks `_test.go` files too, so #257's `large_ksk_test.go` and
main's ~60 new test files all compile against the merged tree. (Build was the
default profile — PQ/liboqs-tagged files were not exercised; see §8.)

## 7. Recommended path forward

You dislike rebasing and want to avoid rewriting history. Good — this merge does
**not** need a rebase. The natural, history-preserving move:

**Option A — merge `origin/main` into the #257 branch (recommended).**
1. On `imr-transport-selection-wip`: `git merge origin/main`
2. Apply the four resolutions from §4 (they are already worked out and verified).
3. **GPG-signed** merge commit (`git commit -S`), no `--no-gpg-sign`.
4. `go build ./... && go vet ./...` (already green in the scratch tree).
5. Push; PR #257 updates in place. No force-push, no history rewrite.

This is exactly what the scratch run proved works. The merge commit records the
209-commit catch-up honestly.

**Option B — merge the tip of #275 instead of main.** You floated this. I'd
**hold off**: #275 (`feature/alg-registry-generator`) is a large, still-open
branch that *also* rewrites the algorithm/config area. Merging its tip would
likely reintroduce conflicts in the very same `dnssec:` config cluster, plus new
ones, and couples #257's fate to #275's review. Cleaner to merge plain `main`
now (small, proven), let #275 land on `main` through its own PR, and — if
needed — do a second trivial catch-up merge into #257 afterward.

**Not recommended: rebase #257 onto main.** It buys nothing here (only 2 commits
to replay), rewrites the PR's history, and you've said you dislike it.

## 8. What this analysis does *not* cover

The merge mechanics are settled and verified to compile. The original reason
#257 stalled — **it was never properly tested** — is unchanged and still the
real work:

- **Run the suite**: `go test ./...` in `v2` (and `cmdv2/...`) with the proper
  build env (`GOROOT=/opt/local/lib/go`, and the `WITH_LIBOQS/SQISIGN/QRUOV`
  env if you want the PQ-tagged paths). This dry-run only did `build` + `vet`.
- **Exercise the transport-selection feature end-to-end** against real/large-KSK
  child zones: the four `dnskey_query_transport` modes (`force_udp`,
  `use_ds_signal`, `try_encrypted`, `force_encrypted`).
- **Re-validate the `large_algorithms` name path specifically.** #257 was
  authored against codepoints; the merged world is name-based. Confirm that a
  sample config with `large_algorithms: [ RSASHA512 ]` (and an unknown name)
  behaves as intended: known name → codepoint set populated; unknown name →
  hard config error.

None of these are merge-conflict work; they're the #257 acceptance testing that
was always outstanding.

## 9. Reproduce / inspect

The resolved merge is sitting un-committed in the scratch worktree:

```
cd /Users/johani/src/git/tdns-project/tdns-257-mergetest
git status                # 3 formerly-conflicted files staged/resolved
git diff --stat HEAD      # what the merge brings in
cd v2 && GOROOT=/opt/local/lib/go /opt/local/lib/go/bin/go build ./...
```

To throw it all away (nothing else is affected):

```
git merge --abort   # if you haven't already
git worktree remove --force /Users/johani/src/git/tdns-project/tdns-257-mergetest
git branch -D scratch/test-merge-main-into-257
```
