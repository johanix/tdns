# tdns-imr under Deckard: a test clock and the switches it needs

**Written 2026-09-28.** Line references are to main at `4711137e`. Deckard
references are to its repository at `e51f539` (2026-06-25).

**Status:** proposal, revision 2. The questions in §9 were decided
2026-09-28. Stage 1, the harness, ran 2026-09-29: see §11, which amends the
S4 prediction.

**Revisions:**
- **r1**, 2026-09-28: `f89c6fea` (#822).
- **r2**, 2026-09-29, after an external review of r1 (verdict: sound, merge):
  - `rrset_cache.go:74`, `DnskeyCacheT.Set`, is data time (§3.2);
  - S3 is required whenever the clock is on, not only to stop a query
    (§3.3, §4);
  - S4 is the existing `PrimeFromHintsOnly` at start-up, not a new priming
    path (§4);
  - header-flag mismatches under `MATCH all` are named as their own class
    (§6, §7);
  - notes on unknown config keys in stage 1 (§6) and on short TIME_PASSES
    steps (§3.3).

## Summary

- **Deckard.** CZ.NIC's black-box test harness for recursive resolvers. It
  runs the resolver in a Linux network namespace and answers its queries from
  scripted scenarios. Knot Resolver runs its whole corpus against it in CI, and
  its resolver set is 191 scenarios. They cover:
  - iteration;
  - DNSSEC validation, including NSEC and NSEC3 denial;
  - CNAME and DNAME chains;
  - caching and TTLs;
  - lame servers and TC fallback.
- **tdns-imr can run under it**, with partial coverage at first:
  - Networking needs nothing: the namespace captures Go's sockets like any
    other.
  - tdns-imr already takes an arbitrary root hints file, an Unbound-style
    trust-anchor file and a listen address, and exits on SIGTERM.
- **Two things stand in the way**, and this document designs both:
  1. **The clock.** Deckard fakes time with libfaketime, which cannot reach a
     Go binary. 129 scenarios pin a validation date (signatures from
     2007–2021), and 20 advance time mid-test. The proposal is a test clock in
     the resolver that reads Deckard's timestamp file itself (§3).
  2. **Unscripted queries.** Deckard fails a scenario when the resolver sends
     a query the scenario did not script. tdns-imr sends some that other
     resolvers do not: startup trust-anchor fetches, AAAA lookups when a
     scenario says `do-ip6: no` (156 scenarios), a root refresh, and a random
     choice of nameserver names to resolve. The proposal is a small set of
     switches (§4).
- **Stages** (§6):
  - The harness alone runs the 42 unsigned `iter_*` scenarios that need no
    clock.
  - The switches make those, and the rest of `iter_*`, deterministic.
  - The clock opens the ~130 DNSSEC scenarios.
- **Accepted gaps.** Some scenarios fail for known differences, which stay on
  a skip list (§7): QNAME minimisation, negative trust anchors, NSEC3 AD bits,
  DSA and Knot-Resolver modules.

## 1. Deckard, as far as it concerns tdns-imr

- **Network** (`contrib/namespaces.py`, `networking.py`).
  - Each test runs in a new user and network namespace with a dummy interface.
  - Every address a scenario names is bound on UDP and TCP port 53.
  - Traffic to any other address is dropped.
  - The resolver needs no changes and no root. The kernel must allow
    unprivileged user namespaces, and the host must be Linux.
- **Time** (`deckard.py:36-54`, `pydnstest/scenario.py:616-627`).
  - Deckard runs under `faketime` with `FAKETIME_NO_CACHE=1` and
    `FAKETIME_TIMESTAMP_FILE=<tmpdir>/.time`, and children inherit both.
  - The file holds `@YYYY-mm-dd HH:MM:SS` in local time. It is written from
    the scenario's `val-override-date` or `val-override-timestamp`, or from
    real time if the scenario has neither.
  - `TIME_PASSES ELAPSE n` reads the timestamp, adds n seconds, and replaces
    the file atomically.
  - Under libfaketime's "@" (start-at) semantics, a process sees the file's
    time plus the real time elapsed since it started.
- **Strictness.**
  - A query that matches no scripted entry gets SERVFAIL and fails the
    scenario, even when the final answer is right (`deckard.py:227`).
  - Scripted entries match on opcode, qname and qtype, and never on the
    query's flags. So the RD=1 of #817 does not break matching.
  - About 235 of ~370 answer checks use `MATCH all`: every header flag, and
    the record count in each section. TTLs and record order are not compared.
- **Starting the resolver** (`deckard.py:92-172`).
  - Jinja2 templates are rendered into the working directory, and the binary
    is started in the foreground.
  - Deckard waits up to 5 s for a TCP connect to `SELF_ADDR:53`, then sends
    UDP queries.
  - SIGTERM ends it, and a non-zero exit fails the test.
- **Template variables** (`scenario.py:852-877`):
  - `ROOT_ADDR` and `ROOT_NAME` (the scenario's root server);
  - `TRUST_ANCHORS` (DS or DNSKEY RR text);
  - `NEGATIVE_TRUST_ANCHORS`;
  - `QMIN`, `DO_IP4`, `DO_IP6`, `HARDEN_GLUE`, `FORWARD_ADDR`, `FEATURES`;
  - from `deckard.py`: `SELF_ADDR` and `WORKING_DIR`.

What the resolver set asks for:

| CONFIG | Scenarios | Needs |
|---|---|---|
| `stub-addr` (root server) | 189 | root hints file (have) |
| `trust-anchor` | 129 | trust-anchor file (have) and the clock (§3) |
| `val-override-date`/`-timestamp` | 121 + 8 | the clock |
| `TIME_PASSES` | 20 | the clock, running |
| `do-ip6: no` | 156 | S1 (§4) |
| `query-minimization: on` / `off` | 5 / 95 | none for `off`; `on` is skipped |
| `domain-insecure` (NTA) | 2 | skipped |
| `forward-addr` | 1 | forward zone (have), S6 |
| `feature` (Knot Resolver modules) | 13 | skipped |

- **Priming:** 176 scenarios script the root `. NS` query. The other 15 do
  not.
- **Clock-free scenarios:** 50 have neither a trust anchor nor TIME_PASSES:
  42 `iter_*` and 8 `module_*`.

## 2. What tdns-imr brings already

- **Root hints.** `imrengine.root-hints` is any zone-file hints: `. NS` plus
  glue, any names and addresses (`cache/rrset_cache.go:881-1040`). Deckard's
  own `template/hints_zone.j2` writes exactly that.
- **Trust anchors.** `imrengine.trust-anchor-file` is Unbound-style, one DS or
  DNSKEY per line, for any owner (`imrengine.go:1955-2013`).
- **Listening.** `listeners.addresses: [ {{SELF_ADDR}}:53 ]` with
  `transports: [ do53 ]`. That needs no certificate and no KeyDB
  (`main_initfuncs.go:135-145`).
- **Required config.** Start-up needs `log.file` and `apiserver.apikey`
  (`apirouters.go:55-58`); a template supplies both.
- **Shutdown.** SIGTERM cancels the context and the daemon exits 0
  (`cmdv2/imr/main.go:21-31`).
- **Queries that are already off.** `revalidate-ns` and the
  `query-for-transport*` options default off. Transport-signal lookups happen
  only for clients asking for strict privacy. `use-transport-signals:false`
  removes the experimental EDNS option from outgoing queries; it causes no
  failures, but it keeps the wire plain.

## 3. The test clock

### 3.1 Data time and elapsed time

The resolver reads the clock for two different reasons, and only one of them
may follow a fake clock:

- **Data time** is compared against DNS data and must follow the scenario:
  - RRSIG inception and expiration;
  - cache expiry and the TTL served from the cache;
  - the TTL cap to a signature's expiry;
  - negative-cache and verdict ages (`ZoneStateRecheck`);
  - a server's address expiry.
- **Elapsed time** measures the resolver's own work and must stay real:
  - query timeouts, RTT samples, backoffs and family-suspect windows;
  - discovery cool-downs, timers and logging.

  A `TIME_PASSES ELAPSE 3600` that reached these would time out every query
  in flight and lift every backoff at once.

So the change is a resolver clock for data time, `cache.Now()`, and the
data-time reads move to it. Everything else keeps `time.Now()`.

The `cache` module is the right home:
- the data-time reads live there, and v2's resolver code already imports it;
- the auth side does not use it, so tdns-auth is untouched.

### 3.2 Where data time is read

**Signature validity and TTL caps** (`cache/rrset_validate.go`):
- the validity window: `:315` and `:620`;
- the TTL caps to RRSIG expiry: `:336-338` and `:630-632`;
- DNSKEY cache expiry: `:202`, `:756`, `:820` and `:880`;
- the verdict age check: `:395`;
- the log lines at `:348` and `:623`.

These have to move together. With only the validity window on the fake clock,
`time.Until(sig.Expiration)` in the TTL caps is taken against real time,
comes out negative for a 2010 signature, and is cast to `uint32`.

**Cache expiry:**
- `cache/rrset_cache.go:50`, `:54`, `:74`, `:133`, `:183`, `:801` and `:840`.
  `:74` is `DnskeyCacheT.Set`, which caps a learned key's expiration with
  `limits.bound(..., now)`. Left on real time, a 2010 clock would keep the
  DNSKEY cache's lifetimes in the present;
- `RemainingTTL(now)` (`cache/cached_ttl.go:27`) already takes `now`, and its
  callers pass `cache.Now()`;
- the verdict age: `cache/cache_structs.go:156-173` and
  `cache/zone_state_recheck.go`.

**Expirations computed in v2:** about 20 `Expiration: time.Now().Add(...)` and
`SetExpire(time.Now().Add(...))` sites in `v2/dnslookup.go`, from `:474` to
`:3579`. Some of them are overwritten by `Cache.Set` anyway (`:3236`, `:3561`,
`:3579` say so). All of them move, so no entry is ever stamped with a real
expiry.

**Stays on real time:**
- backoffs: `cache/authserver.go`, `cache/zone_errors.go`,
  `cache/family_tracker.go`;
- discovery cool-downs: `cache/discovery_state.go`;
- RTT, timeouts and timers across `v2/imr*.go` and `v2/dnslookup.go`.

**Scale:** about 42 clock reads in `cache` and 66 in the IMR files of `v2`.
Roughly a third are data time. The rest are left alone and listed as such in
the PR.

**A trap.** A `time.Time` from `time.Now()` carries a monotonic reading. When
both operands of `Before`, `After` or `Sub` carry one, Go compares the
monotonic readings and ignores the wall clock. So the fake clock returns times
without one (`Round(0)`), and a data-time value must never be compared with a
raw `time.Now()`. The unit tests in §8 check that by running the cache on a
clock set decades back.

### 3.3 The faketime source

- **Parse.** Accept only the format Deckard writes: `@` followed by
  `YYYY-MM-DD HH:MM:SS`, trailing whitespace allowed, parsed with
  `time.ParseInLocation` in `time.Local`. Deckard and the resolver share the
  environment, including `TZ`. Anything else is an error.
- **Semantics.** fake now = file time + (real now − the clock's start).
  - That is libfaketime's start-at behaviour.
  - A TIME_PASSES rewrite moves the file time and keeps the real-time part.
  - The resolver starts a moment after Deckard, so the two clocks differ by
    seconds. That is irrelevant to validity windows of days and to TTL steps
    of hours.
  - The real time a test takes adds to every TIME_PASSES step. Under
    libfaketime that is true for every resolver. It matters only for short
    steps: 5 scenarios advance by 5–25 s. Before a near-expiry miss there is
    treated as a cache or validator bug, measure how far the fake clock had
    run.
  - **The root refresh is off while the clock is on** (S3, §4). Its wait is
    `time.Until(crrset.Expiration)` (`imr_root_refresh.go:178-180`): an
    expiry stamped by `cache.Now()` measured against the real clock. Setting
    `faketime` turns the refresh off, and `root-refresh: true` beside it is a
    config error. In production both stay on real time, so the refresh keeps
    `time.Until`.
- **Re-reading.** `FAKETIME_NO_CACHE=1` asks for a re-read on every clock
  read.
  - The source stats the file on each `Now()` and re-parses when its mtime,
    size or inode changes. Deckard replaces the file with a rename.
  - That is a syscall per data-time read, in tests only.
  - A file that cannot be read after start-up keeps the last good value and
    logs once. A scenario that then fails says why.
- **Activation.** Only by explicit config, never from the environment alone:

  ```yaml
  imrengine:
     testing:
        faketime: true              # read $FAKETIME_TIMESTAMP_FILE
        # faketime-file: /path      # or name the file directly
  ```

  - If `faketime` is set and the file is missing or unparseable, start-up
    fails.
  - When the clock is active, the daemon logs a WARN banner at start and
    every hour, and the resolver's status report (`imr_status.go`) shows it.
  - `config check` flags any `testing:` key.
- **Without the config,** `cache.Now()` is `time.Now()` behind one atomic
  pointer load. The production cost is that load.

### 3.4 One step or two

A validation-only clock (§3.2's first group) would open the scenarios with a
fixed date and no TIME_PASSES: 129 need a date, 20 need time to pass. It is a
smaller first PR, but it leaves cache expiry on real time while signatures
are on scenario time. The proposal does both in one change: the second group
is mechanical once `cache.Now()` exists, and it is what TIME_PASSES needs.

## 4. The switches

Every switch below exists to stop a query a scenario did not script. Only S1
is useful in production; the others sit under `imrengine.testing:` beside the
clock, and `config check` flags them.

| | Switch | Stops | Scenarios | Where |
|---|---|---|---|---|
| S1 | `imrengine.address-families: [ ipv4 ]` (default both) | AAAA lookups for nameserver names; use of AAAA glue and AAAA hints | 156 (`do-ip6: no`), 5 (`do-ip4: no`) | `lookupServerAddrs` (`imr_zone_servers.go:70`), glue at `dnslookup.go:680-700` and `:2040-2060`, hints seeding (`cache/rrset_cache.go:881-1040`), `AuthServer.AddAddr` (`cache/authserver.go:132`) |
| S2 | `testing.anchor-prefetch: false` | the start-up NS and DNSKEY fetch for each anchored zone | most of the 81 anchored below the root | `imrengine.go:479-483`, `:2270`, `:2347` |
| S3 | `testing.root-refresh: false`, implied by `faketime` | the `. NS` refresh before expiry, and its mixed-clock arithmetic | every scenario run with the clock | `imrengine.go:495`, `imr_root_refresh.go:178-180` |
| S4 | `testing.priming: false` | the priming `. NS` query | 15 without a scripted `. NS` | `InitImrEngine` calls `PrimeFromHintsOnly` (`cache/rrset_cache.go:1076-1085`) instead of `PrimeWithHints` (`:1047`); `imrengine.go:321-339` |
| S5 | `testing.ns-pick: ordered` | the random choice of nameserver names to resolve | referrals without glue | `dnslookup.go:3001-3021` |
| S6 | `testing.forward-probe: false` | the SOA probe of forward upstreams | 1 (`forward-addr`) | `imrengine.go:488` |

**S1, address families.**
- Under `ipv4`:
  - AAAA glue and AAAA hints are dropped when they are read;
  - `lookupServerAddrs` asks for A only;
  - `AddAddr` refuses an IPv6 address, as a backstop.
- `ipv6` is the mirror image.
- The family tracker still demotes a failing family; S1 just removes one
  family up front.
- It is worth having in production, on single-stack hosts. Today tdns-imr
  there sends AAAA lookups and IPv6 queries that can only fail. It is
  documented as a production setting in `guide/config-tdns-imr.md` (§9).

**S2, anchor prefetch.**
- The prefetch runs beside the listeners at start-up and queries the anchored
  zone's NS and DNSKEY RRsets.
- A scenario anchored at `example.com.` scripts the DNSKEY fetch the
  validation itself makes. It rarely scripts a standalone NS query for the
  anchor at start-up; Unbound does not send one.
- The comment at `imrengine.go:472-478` says an anchored zone's DNSKEY is
  fetched on demand when no prefetch happened. S2 relies on that path.

**S3, root refresh.**
- It re-queries `. NS` 60 s before expiry, on a real timer against the cached
  TTL.
- Under the fake clock it is wrong as well as noisy. Its wait,
  `time.Until(crrset.Expiration)` (`imr_root_refresh.go:178-180`), measures a
  fake-time expiry against the real clock.
  - On a 2010 clock every root NS already looks expired.
  - After a TIME_PASSES jump the cache has expired the root while the refresh
    still counts in real time.
- So `faketime` implies S3 (§3.3), and the switch also exists on its own for
  runs without the clock.

**S4, priming.**
- The listeners start only after priming succeeds (`imrengine.go:430-441`),
  and a failed priming retries after 5 s (`imr_init_retry.go:27-42`).
- A scenario without a scripted `. NS` therefore never becomes ready within
  Deckard's 5 s.
- S4 needs no new code path.
  - `PrimeFromHintsOnly` (`cache/rrset_cache.go:1076-1085`) seeds the cache
    from the hints and marks it primed without the `. NS` fetch. `RefreshRoot`
    already uses it to re-prime a root that is gone.
  - With S4, `InitImrEngine` calls it instead of `PrimeWithHints`, and
    nothing fetches `. NS`.
- Knot Resolver's Deckard template disables priming the same way
  (`kresd.j2:103-121`).

**S5, ordered picks.**
- When a referral arrives without glue for out-of-bailiwick nameservers, the
  resolver shuffles the names and resolves a budget of them in the background
  (`dnslookup.go:3001-3021`).
- The shuffle spreads load across a resolver population. In a scenario it
  makes the queries random, and a run fails whenever the pick lands on a name
  the scenario only lists.
- `ordered` takes the first names in the NS RRset's order.
- This may not be enough: a scenario may script fewer address lookups than
  the budget. The first run will show (§6), and a `testing.ns-budget` could
  follow.

**S6, forward probe.** The start-up SOA probe of each forward upstream is not
something the one forwarding scenario scripts.

**Not switches:** QNAME minimisation, negative trust anchors and
validation-off. tdns-imr has none of them, and scenarios that need them go on
the skip list (§7).

## 5. The harness

**Where.** It lives in the tdns repository, under `tests/deckard/`:
- `configs/tdns-imr.yaml`;
- `template/tdns-imr.j2`, plus a trust-anchor template;
- `run.sh`, which fetches Deckard at a pinned commit and runs
  `sets/resolver` with the skip list;
- `skip.txt`, with a reason on every line;
- a README.

Deckard itself is not vendored.

**Program config.** Deckard starts `binary` with `additional` as its
arguments. `env` sets the Go runtime option that 20 scenarios' 512-bit RSA
keys need, since Go 1.24+ rejects RSA keys under 1024 bits without it:

```yaml
programs:
- name: tdns-imr
  binary: env
  additional: [ "GODEBUG=rsa1024min=0", "tdns-imr", "--config", "tdns-imr.yaml" ]
  templates: [ template/tdns-imr.j2, template/hints_zone.j2, template/tdns-imr-ta.j2 ]
  configs:   [ tdns-imr.yaml, hints.zone, ta.keys ]
```

**Config template**, in outline:

```yaml
listeners:
   addresses:  [ "{{SELF_ADDR}}:53" ]     # an IPv6 SELF_ADDR needs brackets
   transports: [ do53 ]
imrengine:
   root-hints: "{{WORKING_DIR}}/hints.zone"
{% if TRUST_ANCHORS %}
   trust-anchor-file: "{{WORKING_DIR}}/ta.keys"
{% endif %}
{% if FORWARD_ADDR %}
   forward: [ { zone: ".", addresses: [ "{{FORWARD_ADDR}}" ] } ]
{% endif %}
   options: [ "use-transport-signals:false" ]
   address-families: [ {% if DO_IP4 == "true" %}ipv4, {% endif %}{% if DO_IP6 == "true" %}ipv6{% endif %} ]
   testing:
      faketime: true
      anchor-prefetch: false
      root-refresh: false
      priming: false
      ns-pick: ordered
      forward-probe: false
apiserver:
   apikey: "deckard"
log:
   file:  "{{WORKING_DIR}}/tdns-imr.log"
   level: debug
```

- `ta.keys` holds one `TRUST_ANCHORS` entry per line.
- `hints.zone` is Deckard's own `hints_zone.j2`.
- The forward stanza follows `ImrForwardConf`'s real field names when written.

**Where it runs.**
- Linux only. On Ubuntu 24.04, including GitHub's runners, unprivileged user
  namespaces need `sysctl kernel.apparmor_restrict_unprivileged_userns=0`.
- Deckard and Knot Resolver's CI use privileged containers instead.
- A developer on macOS runs it in a Linux VM.
- It is run by hand with `run.sh` on a Linux host. There is no CI job for now
  (§9).

## 6. Stages

1. **Harness, no code change.**
   - Write the config, the template and the run script, and run the 42
     clock-free `iter_*` scenarios.
   - Record which fail and why. S1–S6 are the prediction, and this run is the
     test of it.
   - 49 of the 50 clock-free scenarios say `do-ip6: no`. Where every
     nameserver has A glue, tdns-imr sends no AAAA lookups, so some will pass
     even before S1.
   - The template can carry the full `testing:` block and `address-families`
     from the start. At start-up an unknown config key is logged as a
     warning ("unknown config keys ignored") and skipped, so the keys do
     nothing until they exist. A reload decodes `imrengine` strictly and
     would reject them, but Deckard never reloads.
   - Until S4, the priming `. NS` query goes out. The 15 scenarios that do not
     script it fail on that alone.
   - Sort the failures by cause. A header flag (RA, AA, AD) that differs
     under `MATCH all` is its own class (§7): neither the clock nor a switch
     fixes it, so it must not be chased as either.
2. **S1 to S6**, one commit each, with unit tests. S1 also documents
   `address-families` in the guide.
   - Re-run `iter_*`, and add the scenarios that now pass to the expected set.
3. **The clock** (§3): `cache.Now()`, the faketime source, and the data-time
   reads moved over, with unit tests.
   - Run the whole set.
   - The first things to look at are `val_*`, `nsec*` and the 20 TIME_PASSES
     scenarios.
4. **Maintenance.**
   - The skip list shrinks as tdns-imr gains QNAME minimisation, NTAs or
     NSEC3.
   - A scenario that newly passes is removed from it. `run.sh` reports that
     rather than ignoring it.

**Size, rough:**
- the clock: 150–250 lines plus tests;
- S1: about 60;
- S2–S6: 10–20 each;
- the harness: about 150, mostly template and script.

## 7. The skip list to start from

| Group | Files | Why |
|---|---|---|
| `module_*` and scenarios with `feature` | 11 + | Knot Resolver's Lua modules |
| `query-minimization: on` | 5 | tdns-imr has no QNAME minimisation |
| `domain-insecure` | 2 | no negative trust anchors |
| DSA (algorithm 3) keys | 9 | expected to fail until the validator has DSA; confirm in stage 3 |
| NSEC3 denials with an expected AD | to be counted in stage 3 | tdns-imr validates NSEC3 denials as Indeterminate (`cache/rrset_validate.go:1214-1221`) |

| Header flags under `MATCH all` | counted in stage 1 and 3 | about 235 answer checks compare every header flag; an RA, AA or AD that differs from the scenario is a behaviour difference, not a clock or switch problem |

Anything else that fails goes on the list with its reason, or gets an issue.
A flag mismatch that shows a tdns-imr bug gets an issue. One that reflects a
deliberate difference stays on the list, with its reason.

## 8. Tests (unit, in tdns)

- **Clock parse:** the `@` format in a named zone; bad formats rejected;
  trailing newline accepted.
- **Clock semantics:**
  - file time plus elapsed time;
  - a rewrite with `+3600` moves `cache.Now()` by an hour;
  - a rewrite is noticed without a restart.
- **Data time only:**
  - with the clock set to 2010, a record cached with TTL 300 expires after a
    rewrite with `+301`, and is served with its TTL counting from the fake
    time;
  - a server's backoff set in the same test still runs on real time;
  - a 2010 RRSIG validates, and the TTL cap is the signature's remaining
    lifetime at fake time, not zero or a wrapped `uint32`.
- **S1:** under `ipv4` only, a referral with AAAA glue and a glue-less
  out-of-bailiwick nameserver produces A queries only. The recorded query log
  of a test double shows no AAAA.
- **S2–S4, S6:** each switch removes its query from the double's log, and
  start-up still completes.
- **S5:** two runs over the same referral send the same address lookups.
- **Activation:**
  - `faketime: true` with no file fails start-up;
  - `faketime: true` turns the root refresh off, and `root-refresh: true`
    beside it is a config error;
  - without `testing:`, `cache.Now()` is real time.

## 9. Decisions

Decided 2026-09-28 (Johan):

1. **The `testing:` block.** The test-only switches and the clock live under
   `imrengine.testing:`, and `config check` flags them.
2. **Where the harness lives:** in the tdns repository, under
   `tests/deckard/`.
3. **CI or manual:** manual. `run.sh` is run by hand on a Linux host, and
   there is no CI job for now.
4. **S1 outside testing:** `address-families` is a production setting,
   documented in the guide for single-stack hosts.

## 10. Not in scope

- **Making tdns-imr's answers match Unbound's.** Where `MATCH all` fails on a
  deliberate difference, the scenario is skipped with the reason. Behaviour
  changes come through issues of their own.
- **QNAME minimisation, NTAs and a validation-off mode.**
- **The RD=1 on iterative queries (#817).** It does not affect Deckard, whose
  scripted entries never match on a query's flags.

## 11. Amendment, 2026-09-29: what stage 1 showed

The harness (`tests/deckard/`) ran the clock-free set on main at `a62d9585`.
The record is `tests/deckard/RESULTS.md`.

- **S4 is needed by every scenario, not 15.**
  - Deckard starts the resolver and waits for it to accept TCP on port 53
    before it starts the scenario's servers (`process_file` calls
    `setup_daemons`, then `run_testcase`).
  - At start-up there is therefore nothing to answer. tdns-imr primes before
    it opens its listeners, and retries after 5 s, so it never becomes ready.
  - §4 counted the scenarios that do not script `. NS`. The timing makes S4 a
    precondition for all of them, and it comes first in stage 2.
- **S2 has the same cause.** The anchor prefetch also runs at start-up, while
  no server answers. Its queries are lost rather than counted as unscripted.
  The first DNSSEC run will show whether that matters.
- **With an experimental S4, 31 of the 40 clock-free scenarios pass.**
  - The 9 that fail get the answer wrong (SERVFAIL where NOERROR or NXDOMAIN
    is expected, or NOERROR where SERVFAIL is), or time out.
  - None failed on an unscripted query or on a header flag.
  - So S1 and S5 did not come up either: no scenario in this set failed on
    an AAAA lookup or on a nameserver pick.

