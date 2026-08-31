# tdns-imr configuration

`tdns-imr` is the TDNS iterative/recursive resolver. For how to run it — daemon
mode versus the interactive shell — see [tdns-imr](app-tdns-imr.md).

Read [Configuration Guide](configuration.md) first for the conventions common to
every TDNS application.

## The block is named `imrengine:`

Almost all of the resolver's configuration lives under a top-level block called
**`imrengine:`**, not `imr:`. The only `imr.`-prefixed key is
`imr.localconfig`, described at the end of this page.

## Minimal working example

Three keys are validated as required (`imrengine.addresses`,
`imrengine.transports`, `log.file`), and one more is required in practice:
`apiserver.apikey`. The API router refuses to build without an API key, and
that error aborts startup — even though the resolver would otherwise not need
the API at all.

```yaml
imrengine:
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
| `addresses` | — | **required**. `addr:port` sockets to listen on |
| `transports` | — | **required**. Any of `do53`, `dot`, `doh`, `doq` |
| `certfile` / `keyfile` | — | required for `dot`/`doh`/`doq` |
| `active` | `true` | set `false` to disable the resolver entirely |
| `root-hints` | compiled-in | path to a root hints file |
| `require-dnssec-validation` | `true` | — |

`imrengine.options:` accepts `query-for-transport`,
`always-query-for-transport`, `query-for-transport-tlsa` and
`transport-signal-type`. Transport-signal *processing* is always on: signals
that arrive in the Additional section are applied whether or not these options
are set; the options control whether the resolver goes looking for them.

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

Like stubs, forward zones are read at startup only; there is no reload path.

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
         lame-delegation:   1h    # backoff after a lame delegation
      address-family:
         window-duration:   10m   # observation window for per-family failures
         failure-threshold: 5     # distinct failures before a family is suspect
         suspect-duration:  10m   # how long a family stays suspect
         probe-interval:    30s   # how often a suspect family is re-probed
      discovery:
         retry-after-failure: 30s # transport-signal discovery retry
         max-failures:        3   # give up discovery after this many
      query-budget:              8s     # total wall-clock budget for one query
      upgrade-indirect-cache-hits: true # left unset in code; treated as true
```

The `address-family` group is what demotes a broken IPv6 (or IPv4) path: once
`failure-threshold` distinct failures are seen inside `window-duration`, that
family is treated as suspect for `suspect-duration` and re-probed every
`probe-interval`.

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
   addresses: [ 127.0.0.1:53 ]      addresses: [ 127.0.0.1:5353 ]   # IGNORED
   transports: [ do53 ]             active: false                   # APPLIED
```

The overlay's `addresses` is discarded, because the main file sets that key. Its
`active` is honoured, because the main file does not — so this resolver ends up
disabled, having never listened on either address.

This holds for every key: `root-hints` and `trust-anchor-ds` are both picked up from the overlay when the main file omits them, and both
ignored when it does not.

So `imr.localconfig` is useful for adding local settings, not for overriding
shared ones. If you need to override a key, change it in the main file.
