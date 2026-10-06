# tdns-imr configuration

`tdns-imr` is the TDNS iterative/recursive resolver. For how to run it — daemon
mode versus the interactive shell — see [tdns-imr](app-tdns-imr.md).

Read [Configuration Guide](configuration.md) first for the conventions common to
every TDNS application.

## Two blocks: `listeners:` and `imrengine:`

WHERE the resolver listens lives under `listeners:` — the same schema as in
every tdns app (#446). Resolver BEHAVIOR lives under **`imrengine:`**, not
`imr:` (the only `imr.`-prefixed key is `imr.localconfig`, described at the
end of this page). The pre-#446 keys `imrengine.addresses/transports/
certfile/keyfile` are hard startup errors naming their new homes.

## Minimal working example

Three keys are validated as required (`listeners.addresses`,
`listeners.transports`, `log.file`), and one more is required in practice:
`apiserver.apikey`. The API router refuses to build without an API key, and
that error aborts startup — even though the resolver would otherwise not need
the API at all.

```yaml
listeners:
   addresses:   [ 127.0.0.1:53, '[::1]:53' ]   # required
   transports:  [ do53 ]                       # required

apiserver:
   apikey:  "a-long-random-string"             # required in practice

log:
   file:   /var/log/tdns/tdns-imr.log          # required
   level:  info
```

Everything else defaults. Two caveats:

**`apiserver.addresses` is optional.** Omit it and the management API simply
does not listen, while the resolver runs normally. If you do set it, note that
`apiserver.usetls` defaults to **true**, which then requires `certfile` and
`keyfile`; otherwise the API listener fails to start (the resolver keeps
running).

**No trust anchor is configured by default.** DNSSEC validation is on —
`require-dnssec-validation` defaults to true — but the daemon seeds no root
anchor unless you configure one. The compiled-in root anchor is wired into
`dog`, not into `tdns-imr`. A resolver with no anchor cannot build a chain of
trust. See below.

## Trust anchors

Exactly three forms exist. Note that two use underscores and the third uses
hyphens.

```yaml
imrengine:
   # inline DS record (preferred)
   trust-anchor-ds:      ". IN DS 20326 8 2 E06D44B8...EC8D"

   # or inline DNSKEY
   trust-anchor-dnskey:  ". IN DNSKEY 257 3 8 AwEAAaz/tAm8y..."

   # or an unbound-style file, one DS/DNSKEY per line
   trust-anchor-file:    /etc/tdns/root.key
```

Inspect what the running resolver actually loaded with `show config` in the
interactive shell.

## Transports and listeners

| Key | Default | Meaning |
|-----|---------|---------|
| `listeners.addresses` | — | **required**. `addr:port` sockets to listen on |
| `listeners.transports` | — | **required**. Any of `do53`, `dot`, `doh`, `doq` |
| `listeners.certfile` / `keyfile` | — | required for `dot`/`doh`/`doq` |
| `listeners.ports.{dot,doh,doq}` | 853/443/853 | per-transport listen ports (numbers) |
| `listeners.doh-path` | `/dns-query` | the one HTTP path the DoH listener answers on, matched exactly; every other path gets 404. Same rules as in the [tdns-auth reference](config-tdns-auth.md#the-listeners-and-authengine-blocks). It sets only what this resolver serves: DoH to forwarding upstreams still goes to `/dns-query` |
| `imrengine.active` | `true` | set `false` to disable the resolver entirely |
| `imrengine.root-hints` | compiled-in | path to a root hints file |
| `imrengine.require-dnssec-validation` | `true` | — |

`imrengine.options:` accepts `query-for-transport`,
`always-query-for-transport`, `query-for-transport-tlsa` and
`transport-signal-type`. Transport-signal *processing* is always on: signals
that arrive in the Additional section are applied whether or not these options
are set; the options control whether the resolver goes looking for them. A
strict-privacy query goes looking regardless, for the servers it knows nothing
about, and waits up to `tuning.discovery.strict-wait` for the answers.

## Stub zones

Resolve a zone by asking named **authoritative** servers directly instead of
iterating from the root. The resolver still iterates (RD=0) and follows
referrals below the stub.

`servers:` is a list of objects, not a list of addresses; `addrs:` holds bare
IP literals (no port), and `alpn:` is optional (defaults to `do53`).

```yaml
imrengine:
   stubs:
      - zone:  internal.example.
        servers:
           - name:   ns1.internal.example.
             addrs:  [ 192.0.2.53, 2001:db8::53 ]
             alpn:   [ do53 ]
```

Both `zone` and `servers` are required in each entry.

## Forward zones

Send queries for names at or below `zone:` as **recursive** queries (RD=1) to
one or more upstream resolvers, in configured order — the first usable
response wins. `zone: .` forwards everything. Forwarding is forward-only: when
every upstream of the matching zone fails, the query fails with SERVFAIL;
there is no fallback to iteration.

```yaml
imrengine:
   forward:
      - zone:  foo.bar.
        upstreams:
           - addr:      192.0.2.1
             port:      8853
             transport: doq
             tls-server-name: dns.example.net
      - zone:  company.com.
        upstreams:
           - addr:      9.8.7.6
             port:      5355
             transport: tcp
      - zone:  .                    # forward everything else
        upstreams:
           - addr: 192.0.2.53       # do53, port 53
```

Selection: the most specific matching forward zone wins, and a **more**
specific stub zone wins over a forward zone (so a lab stub can punch a hole
in a `zone: .` forward). Zone cuts learned from referrals never override a
configured forward.

In a daemon that serves zones, such as tdns-auth, a question about a zone
the server serves comes before both: it is answered from the zone. A zone
with the option `modified-downstream`, whose published version is signed or
changed downstream of the server, is not answered from, and its questions go
to stubs, forwards or the root like any other
([zone options](config-tdns-auth.md#zone-options)).

Per upstream:

| Key | Default | Meaning |
|-----|---------|---------|
| `addr` | — | **required**. Bare IP literal (no hostname, no port) |
| `port` | per transport | `do53`/`tcp` 53, `dot`/`doq` 853, `doh` 443 |
| `transport` | `do53` | `do53` (UDP with TCP fallback), `tcp`, `dot`, `doh`, `doq` |
| `tls-server-name` | — | `dot`/`doh`/`doq` only: name the upstream's certificate is verified against (and sent as SNI). Unset: the certificate must carry the `addr` IP in a SAN |
| `insecure` | `false` | `dot`/`doh`/`doq` only: disable certificate verification (self-signed lab certificates) |

Per zone, `trust-ad: true` accepts the upstream's AD bit instead of validating
forwarded answers locally, for positive and negative answers alike. Because a
spoofed AD bit would be cached as secure and re-served with AD=1, `trust-ad`
**requires every upstream of the zone to be encrypted and verified**
(`dot`/`doh`/`doq`, without `insecure`) — the daemon refuses to start
otherwise. Use it toward a trusted, validating upstream.

The default (false) runs forwarded answers through the resolver's own DNSSEC
validation, against its own trust anchors, exactly like iteratively resolved
answers. Forwarded queries then carry CD=1, so a validating upstream hands
over the data (and RRSIGs) even when *its* validator would reject it — the
local verdict is independent of the upstream's. The chain queries (DNSKEY,
DS, per zone level up to a trust anchor) are forwarded to the same upstream;
they are issued on first contact with a zone and the validated keys are
cached, so the burst is per zone per TTL, not per query.

Stub and forward zones are reloadable: `tdns-cli config reload`, `tdns-cli
config reload-zones` and SIGHUP all re-read the `imrengine:` `stubs:` and
`forward:` blocks and apply them to the running resolver, and the reply names
what changed (`IMR zones: forward + internal.example.; stub - old.example.`).
A zone whose configuration is untouched keeps its live state — per-upstream
reachability counters, per-server transport counters and address backoffs —
so reloading one zone does not clear a DEGRADED that is still true, and the
cache is never discarded. A forward table that fails validation is refused
whole: the running one is left exactly as it was and the reply says so.

The rest of `imrengine:` is not reloadable — trust anchors, tuning, options,
root hints and logging are consumed once at startup. Editing one of those and
reloading reports it (`restart required for imrengine.tuning`) rather than
silently ignoring it.

Startup behaviour: when a forward zone covers the root, the live `. NS`
priming fetch is skipped — the hints are seeded offline and the cache is
marked primed, so a forward-all resolver starts (and serves) even when its
upstream is down at boot. Instead, every forward upstream is probed once at
startup with a recursive SOA query for the forward zone itself (an upstream
serving only that zone may legitimately refuse to resolve anything else), in
parallel with normal operation: an
unreachable upstream is WARNed in the log and aggregated into an
`Upstream/ImrForward` server error, which marks `config status` as DEGRADED
and names the upstream. The error clears as soon as any exchange against the
upstream succeeds. Inspect the resolver's state — priming, stub zones, and
per-upstream reachability — with `tdns-cli imr config status` (the same block
appears in `auth config status` / `agent config status` for the embedded
resolver those daemons carry).

## Debug logging

Separate from `log.file`, and off by default.

```yaml
imrengine:
   logging:
      enabled:  true
      file:     /var/log/tdns/imr-debug.log   # this is the default when enabled
```

## Outbound address families

`outbound-address-families` says which IP versions the resolver sends its
queries to authoritative servers over: `ipv4`, `ipv6`, or both, which is the
default. What the resolver listens on is `listeners.addresses`, which binds
exactly the addresses listed.

```yaml
imrengine:
   outbound-address-families: [ ipv4 ]   # or [ ipv6 ], or [ ipv4, ipv6 ]
```

- **What leaving a family out does.** The resolver neither looks up nor uses
  addresses of that family. Glue and root hints of that family are dropped as
  they are read, and a nameserver's addresses are looked up only for the
  family in use. A nameserver whose glue is all of the family left out is
  looked up like one that came without glue.
- **When to use it.** On a host where one family does not work. A host can
  have an IPv6 address and a default route that lead nowhere, while IPv4
  works. With both families in use, such a resolver keeps sending AAAA
  lookups and IPv6 queries that can only fail, until the `address-family`
  tuning group below marks the family as suspect.
- **One family as a measurement.** With `[ ipv6 ]` the resolver reaches only
  what IPv6 alone reaches, which shows how much is lost without IPv4.
- **What it does not touch.** The listeners, as above. A forward zone's
  upstreams are used as configured. A stub zone's servers are not: an
  address of a family left out is dropped, with a log line.

An unknown value is an error: the resolver does not start, and
`config check` reports it. Changing the list takes a restart.

## Tuning

Every key under `imrengine.tuning:` is optional. The values below **are** the
defaults, so this block is only worth writing when you want to change one.
Inspect the effective values on a running resolver with `dump tuning` in the
interactive shell, or `tdns-cli agent imr dump-tuning` against an agent.

```yaml
imrengine:
   tuning:
      backoff:
         first-failure:     15s   # first backoff after a server failure
         max-failure:       1h    # ceiling; raised to first-failure if set lower
         multiplier:        3.0   # exponential growth factor
         jitter-fraction:   0.25  # must be in [0,1), else reset to the default
         routing-failure:   1h    # backoff after an unreachable-network error
         lame-delegation:   5m    # backoff after REFUSED/NOTAUTH (lame); RFC 9520 caps failure caching at 5m
      address-family:
         window-duration:   10m   # observation window for per-family failures
         failure-threshold: 5     # distinct failures before a family is suspect
         suspect-duration:  10m   # how long a family stays suspect
         probe-interval:    30s   # how often a suspect family is re-probed
      discovery:
         retry-after-failure: 30s # transport-signal discovery retry
         max-failures:        3   # give up discovery after this many
         strict-wait:         2s  # how long a strict-privacy query waits for new servers' signals
      query-budget:              8s     # total wall-clock budget for one query
      upgrade-indirect-cache-hits: true # left unset in code; treated as true
      cache-max-ttl:             86400  # seconds; ceiling on cached lifetimes
      cache-min-ttl:             0      # seconds; floor on cached lifetimes (0 = none)
      zone-state-recheck:        30s    # how long an insecure or indeterminate zone verdict stands
      nsec3-max-iterations:      10     # NSEC3 proofs above this are not judged (RFC 9276)
```

The `address-family` group is what demotes a broken IPv6 (or IPv4) path: once
`failure-threshold` distinct failures are seen inside `window-duration`, that
family is treated as suspect for `suspect-duration` and re-probed every
`probe-interval`.

`cache-max-ttl` and `cache-min-ttl` are Unbound's knobs of the same names, with
the same units (seconds, not durations) and defaults. They bound how long
anything learned from the network stays in the cache, positive and negative
answers alike, and because the TTL a client is served is what remains of the
cached lifetime, clients see the bounded TTL too. Root hints and trust anchors
are configuration, not cached data, and are not bounded. When `cache-min-ttl`
exceeds `cache-max-ttl`, the maximum wins.

The lifetime they bound is the smallest TTL among the records an entry holds
and serves. A denial lives for its negative TTL, the smaller of the SOA's TTL
and its MINIMUM field (RFC 2308 section 5), and no longer than the records of
its proof. An entry the resolver has authenticated lives no longer than the
signatures that authenticated it allow (RFC 4035 section 5.3.3): their TTL and
Original TTL count as TTLs, so `cache-min-ttl` raises them like any other, but
the time left to their expiration is a bound that `cache-min-ttl` does not
override. The resolver does not serve AD for data whose signatures have
expired. `cache-max-ttl` still lowers the lifetime of such an entry.

`zone-state-recheck` is how long the resolver acts on a zone's Indeterminate or
Insecure DNSSEC verdict before it looks at the zone again. An Indeterminate zone,
one whose chain of trust could not be followed, has its chain followed afresh. An
Insecure zone, one delegated without a DS, has its parent asked for a DS the next
time a signature from the zone is checked, and a DS that validates makes the zone
secure. A zone whose parent starts publishing a DS therefore validates within
about this interval, with no flush and no restart. Only signed data prompts a
recheck, so a zone that stays unsigned costs nothing, while a signed zone still
delegated without a DS costs one DS query per interval for as long as it is in
use. Flushing a zone without keeping its structural records, or resetting the
cache, drops these verdicts at once.

`nsec3-max-iterations` is the most NSEC3 hash iterations the validator computes
a proof for. RFC 9276 asks zones to use 0, and deployed zones rarely use more
than a few. A denial whose proof needs NSEC3 records above the limit is served
without AD, with EDE 27 (Unsupported NSEC3 Iterations Value), once the records'
signatures have validated; a zone cut such records would prove is not judged,
and the zone below it is treated as indeterminate. 0 is allowed.

## Test-harness switches

`imrengine.testing:` holds switches for black-box test harnesses, such as
`tests/deckard/`. None of them is for production, and `config check` warns
about any that is not at its production default. Leaving `priming` out, or
setting it to `true`, is that default and draws no warning.

```yaml
imrengine:
   testing:
      priming:       false
      faketime:      true           # the clock in $FAKETIME_TIMESTAMP_FILE
      # faketime-file: /tmp/.time   # or name the file
      root-refresh:  false
```

A change to any of them takes a restart.

**`priming: false`**
- **What it does.** It seeds the cache from `root-hints` as they stand and
  marks it primed, without asking the roots for their NS RRset.
- **Why a harness needs it.** A harness that starts its scripted servers only
  once the resolver accepts connections needs this switch. Otherwise the
  resolver opens its listeners only after priming has succeeded, and never
  becomes ready.
- **What still happens.** The root NS is still refreshed from the live roots
  before the hints' copy expires, unless `root-refresh` is false.

**`faketime`, a test clock**
- **What it does.** The resolver's data time becomes a clock read from a
  libfaketime timestamp file. Data time is what DNS data is measured against:
  a signature's validity, a cache entry's expiry, the TTL served from the
  cache.
  - The file holds `@YYYY-MM-DD HH:MM:SS`, in local time.
  - The clock is the file's time plus the real time since the resolver
    started.
  - The file is checked on every read, so a harness moves the clock by
    rewriting it.
  - Timeouts, RTTs and backoffs stay on real time.
- **Why a harness needs it.** Deckard fakes the time with libfaketime, which
  a Go binary ignores, and its DNSSEC scenarios are signed in 2007–2021.
- **Which file.** `faketime-file`, which turns the clock on by itself, or else
  `$FAKETIME_TIMESTAMP_FILE`, which Deckard sets.
- **When it stops the start.** No file, or one that does not parse. A file
  that later cannot be read leaves the last time in force.
- **What it turns off.** The root NS refresh, which waits in real time for an
  expiry in data time. `root-refresh: true` beside it stops the start.
- **Where it shows.** A warning at start and every hour, and a line in
  `config status`.

**`root-refresh: false`**
- **What it does.** It stops the refresh of the root NS before it expires.
  The test clock implies it.

## large-algorithms

Not part of `imrengine:` — it lives in the shared top-level `dnssec:` block.

```yaml
dnssec:
   large-algorithms: [ RSASHA512 ]
```

When a referral's DS RRset names one of these algorithms, the resolver fetches
the child's DNSKEY over TCP from the outset rather than trying UDP and retrying
on truncation.

Entries are algorithm **names**, not codepoints — `[ 10, 8, 5 ]` is a decode
error (`expected type 'string', got unconvertible type 'int'`) that prevents
startup. A name this binary does not know is likewise a hard config error. See
[DNSSEC policies](config-tdns-auth.md#large-algorithms) for the full list of
accepted spellings, and inspect the counters with
`tdns-cli imr stats large-ksk`.

## imr.localconfig

The one `imr.`-prefixed key. It names a second config file, read after the main
one; a missing file is skipped silently.

```yaml
imr:
   localconfig:  /etc/tdns/tdns-imr-local.yaml
```

**The overlay does not override the main config file.** It can only *supply*
keys that the main file leaves unset. Any key the main file defines wins, even
though the overlay is read later.

```yaml
# tdns-imr.yaml                  # tdns-imr-local.yaml
imrengine:                       imrengine:
   root-hints: /etc/tdns/rh         root-hints: /tmp/other-hints    # IGNORED
                                    active: false                   # APPLIED
```

The overlay's `root-hints` is discarded, because the main file sets that key.
Its `active` is honoured, because the main file does not — so this resolver ends up
disabled, having never listened on either address.

This holds for every key: `root-hints` and `trust-anchor-ds` are both picked up from the overlay when the main file omits them, and both
ignored when it does not.

So `imr.localconfig` is useful for adding local settings, not for overriding
shared ones. If you need to override a key, change it in the main file.
