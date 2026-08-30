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
  against its own trust anchors, exactly like iterated answers; the chain
  queries (DNSKEY, DS) are themselves forwarded to the same upstream, so this
  works even when the upstream is the only reachable resolver. AD is set only
  on local validation. Per-zone `trust-ad: true` instead adopts the
  upstream's AD bit — only sensible toward a trusted, validating upstream
  over an authenticated transport.
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
modes: the resolver binds `imrengine.addresses`, starts the validator and the
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
*"No active channel to RecursorEngine. Terminating."* The only `tdns-cli imr`
subcommands that do anything are `imr ping`, `imr daemon ...` and
`imr dsync-query`.

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
