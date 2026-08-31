# tdns-imr

A simple DNS IMR (Iterative Mode Resolver, i.e. a recursive DNS nameserver).

For the configuration file, see
[tdns-imr configuration](config-tdns-imr.md).

Features:

- **tdns-imr** does recursive lookups, caches intermediate referrals and final
  response (if any)

- incoming queries are first matched against the cache before initiating
  lookup via external queries

- supports modern DNS transports (DoT, DoH and DoQ) in addition to Do53 (UDP/TCP).

- besides full iteration, supports **stub zones** (iterate against named
  authoritative servers) and **forward zones** (hand the query to an upstream
  recursive resolver, per zone or for everything). See
  [Resolution modes](#resolution-modes-iteration-stubs-and-forwarding) below.

- consumes transport signals from authoritative nameservers — when an
  SVCB record at `_dns.<ns>` arrives in the Additional section (or via
  active discovery, see `query-for-transport` /
  `always-query-for-transport`), tdns-imr parses SvcParam key 65280,
  updates the server's transport preferences in the referral cache, and
  promotes the connection mode to "opportunistic" so subsequent queries
  attempt the preferred encrypted transport. TSYNC is supported as an
  alternative carrier. See section 2 of
  [TDNS Special Features](special-features.md) for the full picture.

## Resolution modes: iteration, stubs, and forwarding

For any given query the resolver answers from cache when it can, and otherwise
resolves in one of three ways.

**Iteration** is the default: walk the delegation tree from the closest known
zone cut (ultimately the root hints), following referrals, with RD=0 queries
to authoritative servers.

**A stub zone** (`imrengine.stubs:`) pre-seeds the resolver's knowledge of a
zone with named authoritative servers, so iteration for names in that zone
starts there instead of at the root. It is still iteration: RD=0, referrals
below the stub are followed, and the stub's servers must be authoritative.
Use it when a zone is not reachable through the public delegation tree — a
lab parent, a split-horizon internal zone.

**A forward zone** (`imrengine.forward:`) sends the query as a *recursive*
query (RD=1) to one or more upstream resolvers and treats the response as
final — for names under the forward zone, tdns-imr behaves like a stub
resolver toward its upstream. `zone: .` forwards everything. Use it when the
upstream should do the resolving: a central resolver behind a restrictive
firewall, a filtering resolver, or an encrypted-transport hop
(DoT/DoH/DoQ, with certificate verification) to a resolver you trust.

Which mode a query uses is decided per qname:

1. The **most specific** configured forward zone matching the qname wins.
2. A configured stub zone that is **more** specific than that forward zone
   overrides it — so a lab stub can punch a hole in a `zone: .` forward.
3. No forward match: iteration (seeded by any matching stub).

Zone cuts learned from referrals along the way never override a configured
forward zone.

Details of forwarding behaviour:

- **Upstream selection** is ordered failover: upstreams are tried in
  configured order and the first usable response wins. A response counts as
  usable when it is NOERROR or NXDOMAIN and parses as an answer or a
  well-formed negative; SERVFAIL/REFUSED, timeouts, and referral-shaped
  responses move on to the next upstream.
- **Forward-only**: when every upstream of the matching zone has failed, the
  client gets SERVFAIL. There is deliberately no fallback to iteration — an
  operator who confined a zone to an upstream does not want its queries
  leaking to the delegation tree when the upstream is down.
- **DNSSEC**: forwarded answers go through the resolver's own validation
  against its own trust anchors, exactly like iterated answers. Forwarded
  queries carry CD=1 so the upstream hands over data (and RRSIGs) its own
  validator would suppress — the local verdict stays independent. The chain
  is fetched lazily, bottom-up: validating an answer triggers a DNSKEY query
  for the signer zone, validating that DNSKEY triggers a DS query, and so on
  up to a trust anchor — each of these forwarded to the same upstream, so
  validation works even when the upstream is the only reachable resolver.
  There is no way in plain DNS to request the whole chain in one round trip
  (RFC 7901's CHAIN option exists but is essentially undeployed), so first
  contact with a zone costs a short burst of chain queries — typically
  answered from the upstream's cache in one round trip each — and the
  validated keys are cached here, so the burst is per zone per TTL, not per
  query. AD is set only on local validation. Per-zone `trust-ad: true`
  instead adopts the upstream's AD bit, for positives and negatives alike;
  because that bit would otherwise be spoofable, `trust-ad` requires every
  upstream of the zone to be encrypted and verified, enforced at startup.
- **Transports**: each upstream has its own transport (`do53`, `tcp`, `dot`,
  `doh`, `doq`) and port. Encrypted upstreams verify the server certificate
  by default (`tls-server-name`, or the upstream IP in a SAN), with
  `insecure: true` as an explicit per-upstream opt-out for self-signed lab
  certificates. This is independent of — and stricter than — the transports
  the resolver's *listeners* offer.
- **Caching**: forwarded answers and negatives land in the same cache with
  their TTLs; repeat queries are answered from cache without touching the
  upstream. The EDNS0 PR flag (privacy required) is honored: unencrypted
  upstreams are skipped for PR queries, and a forward zone with no encrypted
  upstream answers SERVFAIL with the corresponding EDE.
- **Startup and observability**: a forward zone covering the root skips the
  live `. NS` priming fetch (the hints are seeded offline), so a forward-all
  resolver starts and serves even when its upstream is down at boot. Every
  forward upstream is probed once at startup; an unreachable one is WARNed
  and marks `config status` DEGRADED with an `Upstream/ImrForward` error
  naming it, clearing on the first successful exchange. `tdns-cli imr config
  status` reports priming state, stub zones, and per-upstream reachability —
  and the same IMR block appears in `auth config status` / `agent config
  status` for the resolver embedded in those daemons. A failed IMR init
  (priming failure in iterative mode) also registers an `Upstream/ImrPriming`
  error, so a daemon running without its DNS listeners is visible as DEGRADED
  rather than silently answering nothing. `config status` also reports the
  process's open-descriptor count against its limit (and goroutine count),
  with a warning above 80% — the tdns#443 wedge was fd exhaustion starving
  outbound dials, and this makes that class of leak visible while it grows.
- **Limits**: upstream addresses are IP literals (no hostnames), the DoH path
  is fixed at `/dns-query`, and the forward table is read at startup only —
  like stubs, there is no reload.

Configuration reference and examples for both `stubs:` and `forward:` are in
[tdns-imr configuration](config-tdns-imr.md).

## Daemon mode and interactive mode

**tdns-imr** runs in one of two modes, selected by the `--cli` flag.

```console
$ tdns-imr                       # daemon mode (the default)
tdns-imr: Starting in daemon mode, no CLI

$ tdns-imr --cli                 # interactive mode
```

Interactive mode is **not** a lightweight client. Startup is identical in both
modes: the resolver binds `listeners.addresses`, starts the validator and the
HTTP management API, and begins answering queries. `--cli` merely layers a shell
on top of that running resolver, so every command below inspects and manipulates
the live in-process cache.

The shell is a `go-prompt` REPL with completion. `exit` or `quit` terminates it
— and with it the daemon. A bare `query` with no arguments is also treated as
`quit`.

Other flags: `--config`, `-d`/`--debug`, `-v`/`--verbose`, `--version`,
`-H`/`--headers`, `-z`/`--zone`, `-Z`/`--pzone`. Sending `SIGHUP` triggers a
zone reload.

## Interactive commands

**Querying**

| Command | Effect |
|---------|--------|
| `query <name> <type>` | Resolve in-process and print the answer with its DNSSEC validation state. `-v` also prints the negative proof |

**Cache inspection** — `dump` on its own lists the RRset cache.

| Command | Effect |
|---------|--------|
| `dump suffix <suffix>` | Cached RRsets whose owner name ends in `<suffix>` |
| `dump zones` | All cached zones, with secure-delegation status |
| `dump zone servers <zone>` | Servers known for one zone |
| `dump zone backoffs <zone>` | Lame-delegation backoffs for one zone |
| `dump servers` | Servers, grouped by zone |
| `dump auth-servers` | Authoritative-server table |
| `dump auth-servers servers` | The server entries |
| `dump auth-servers keys` | The cache keys |
| `dump auth-servers errors` | Servers currently in backoff |
| `dump keys` | Cache keys |
| `dump dnskeys` | Trust anchors and cached DS, with validation state |
| `dump tuning` | The effective `imrengine.tuning.*` values |
| `dump discovery` | Transport-signal and TLSA discovery state |

**Cache flushing**

| Command | Effect |
|---------|--------|
| `flush common <domain>` | Flush non-structural RRsets at and below `<domain>` |
| `flush all <domain>` | Flush all RRsets at and below `<domain>`. Refuses the root |

**Statistics**

| Command | Effect |
|---------|--------|
| `stats` | Large-KSK metrics, and lists the subcommands |
| `stats large-ksk` | DNSKEY-over-TCP counters for large algorithms |
| `stats auth-transports <zone>` | Per-transport counters |
| `stats auth-servers <zone>` | Alias of the above |

**Inspection and settings**

| Command | Effect |
|---------|--------|
| `show config` | Listen addresses, cache-primed flag, trust anchors, stub zones |
| `show options` | The configured `imrengine.options` |
| `set linewidth <n>` | Output truncation width |
| `set server transport --server <ns> --signal "doq:20,dot:100,do53:3"` | Override a server's transport signal at runtime (debug). `--reset` clears it |

**Zones**

`zone list` prints only, and `zone check <file>` is not yet implemented.

There is no interactive command to add, remove or reload trust anchors, and no
command to re-prime the cache. Trust anchors are display-only here (`show
config`, `dump dnskeys`); a cache reset exists only over the API. IMR debug
logging is configured with `imrengine.logging.enabled`, not toggled from the
shell.

## Relationship to `tdns-cli imr ...`

Three surfaces exist, and they are easy to confuse.

**The interactive shell** (above) acts on the tdns-imr process it is part of,
through in-process channels.

**`tdns-cli imr <cache-command>` does not work.** `tdns-cli` registers the same
command objects under `imr`, but their implementations reach for an in-process
resolver that `tdns-cli` does not have. `tdns-cli imr query` prints
*"No active channel to RecursorEngine. Terminating."* The `tdns-cli imr`
subcommands that do work are the API-based ones: `imr ping`, `imr daemon ...`,
`imr dsync-query`, `imr config status`, and the `imr forward ...` /
`imr stub ...` trees below.

**`tdns-cli {imr,auth imr,agent imr} forward|stub ...`** inspect and probe the
resolver's forward and stub zones over the `/imr` API — against tdns-imr
directly, or against the resolver embedded in tdns-auth / tdns-agent:

| Command | Effect |
|---------|--------|
| `forward list` | The configured forward zones and upstreams (transport, port, TLS settings) |
| `forward status` | Per-upstream reachability, query/failure counters, last success/error |
| `forward probe [zone]` | Re-run the startup probe now (a recursive SOA query for the forward zone, per upstream) and report per upstream with RTT. **Updates** the live reachability state, so probing confirms a recovery (clearing the DEGRADED error) or surfaces a newly dead upstream. Non-zero exit when any upstream fails |
| `stub list` | The configured stub zones and their servers (name, addrs, alpn) |
| `stub status` | Per-server transport counters (attempted/used/failed/truncated) and any active (address, transport) backoffs — the state that silently disabled stubs in the 2026-08-11 outage |
| `stub probe [zone]` | RD=0 SOA query for the stub zone to every (server, address, advertised transport) tuple; reports rcode, AA bit and RTT. **Strictly report-only**: nothing is recorded, so a probe can never put a stub server into backoff. Non-zero exit when any tuple fails to answer authoritatively |

**`tdns-cli agent imr ...` and `tdns-cli auth imr ...` are the real API-based
cache commands.** They POST to the `/imr` endpoint of a running **tdns-agent**
or **tdns-auth** — each of which embeds its own resolver — not to tdns-imr.

| Command | Wire command |
|---------|--------------|
| `query <qname> <qtype>` | `imr-query` |
| `flush <qname>` | `imr-flush` |
| `reset` | `imr-reset` (flush and re-prime, preserving root NS) |
| `show --id <agent>` | `imr-show` |
| `dump-tuning` | `imr-dump-tuning` |
| `dump-zone-backoffs [zone]` | `imr-dump-zone-backoffs` |

tdns-imr does serve the `/imr` endpoint itself, but no shipped CLI command is
wired to send these cache commands to it.
