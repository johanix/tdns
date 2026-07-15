# tdns-auth configuration

`tdns-auth` is the TDNS authoritative nameserver. This page starts from the
smallest config that runs and then covers, in turn: TSIG keys, the two address
ACLs, zone declarations and the template system, the `dnsengine:` block, and
DNSSEC policies.

Read [Configuration Guide](configuration.md) first for the conventions that
apply to every TDNS application (config file location, `include:`, the
"unknown config keys" warning, zone quarantining).

- [Minimal working example](#minimal-working-example)
- [TSIG configuration](#tsig-configuration)
- [ACL configuration](#acl-configuration)
- [Zone declarations](#zone-declarations)
- [Zone templates](#zone-templates)
- [The dnsengine block](#the-dnsengine-block)
- [DNSSEC policies](#dnssec-policies)

## Minimal working example

`tdns-auth` validates five sections at startup and refuses to run if any
required key in them is missing: `service`, `dnsengine`, `apiserver`, `db` and
`log`. The following is the whole config for a server that listens on one IPv4
and one IPv6 address and serves a single zone as primary.

```yaml
service:
   name:  TDNS-AUTH               # required

dnsengine:
   addresses:   [ 127.0.0.1:5354, '[::1]:5354' ]   # required
   transports:  [ do53 ]                           # required

apiserver:
   addresses:  [ 127.0.0.1:8080 ]                  # required
   apikey:     "a-long-random-string"              # required
   certfile:   /etc/tdns/certs/api.crt             # required, must exist
   keyfile:    /etc/tdns/certs/api.key             # required, must exist
   usetls:     false

db:
   file:  /var/lib/tdns/tdns-auth.db               # required; created on first run

log:
   file:   /var/log/tdns/tdns-auth.log             # required
   level:  info

zones:
   - name:      example.com.
     type:      primary
     zonefile:  /etc/tdns/zones/example.com.zone
     downstreams:                                  # who may AXFR from us
        - prefix:  "127.0.0.0/8"
          key:     NOKEY
        - prefix:  "::1"
          key:     NOKEY
```

Three things about this are easy to get wrong.

**`apiserver.certfile` and `apiserver.keyfile` are required even when
`usetls: false`.** They are validated as an existing, matching certificate/key
pair regardless of whether TLS is switched on, so a server with no API TLS
still needs a cert on disk. `apiserver.addresses` and `apiserver.apikey` are
likewise required — there is no way to run tdns-auth without its management API
being configured, though you may point it at loopback.

**`transports: [ do53 ]` needs no certificate, but `dot`, `doh` and `doq` all
need `dnsengine.certfile`/`keyfile`.** If those are missing, the encrypted
listeners are quietly skipped while Do53 keeps working.

**Without `downstreams:` no one can transfer the zone.** An empty or absent
`downstreams:` ACL denies every AXFR/IXFR. This is deliberate — it closes the
old open-by-default behaviour — but it means a freshly configured primary will
refuse its own secondaries until you say otherwise. See
[ACL configuration](#acl-configuration).

Zones are usually kept in a separate file and pulled in with `include:`; see
[`auth-zones.sample.yaml`](../cmdv2/auth/auth-zones.sample.yaml).

## TSIG configuration

TSIG keys may be declared statically in the config file, or added at runtime to
the keystore. Both end up in the same place: the keystore lives in the SQLite
database named by `db.file`, and there is no separate keystore path to
configure.

```yaml
keys:
   tsig:
      - name:       xfr-key-2026.       # required
        algorithm:  hmac-sha256         # required
        secret:     "base64-secret=="   # required
        owner:      rollover-2026       # optional label
```

Supported algorithms are `hmac-sha1`, `hmac-sha224`, `hmac-sha256`,
`hmac-sha384` and `hmac-sha512`.

Keys declared here are synchronised into the keystore at startup as
`origin=config` rows, and the in-memory cache is then rebuilt from the
database. Keys added at runtime are stored with `origin=keystore`:

```console
$ tdns-cli auth keystore tsig add --name xfr-key-2026. \
      --algorithm hmac-sha256 --secret-file /root/newkey.b64
```

Prefer `--secret-file` over `--secret`: an inline secret is visible in your
shell history and in the process list.

`owner:` is a free-text provenance label shown by
`tdns-cli auth keystore tsig list`. It does **not** scope the key to a zone and
grants no authority of its own; it defaults to the key's origin.

Two names are reserved and may not be used as key names: **`NOKEY`** and
**`BLOCKED`**. Both are ACL sentinels, described next.

A key name referenced from a zone's `primaries:`, `notify:`, `allow-notify:` or
`downstreams:` must resolve, either here or in the keystore. If it does not,
that zone is quarantined at config load:

```
Error[config]: downstreams: acl entry "192.0.2.0/24": unknown key "xfr-key-2026"
```

## ACL configuration

Two zone-level keys are address ACLs. They share a grammar and differ only in
what they guard:

| Key | Side | Guards | Empty means |
|-----|------|--------|-------------|
| `downstreams:` | primary | who may AXFR/IXFR **from** us | **deny everyone** |
| `allow-notify:` | secondary | who may send NOTIFY **to** us | accept unsigned NOTIFY from any configured primary's address |

Both are ordered lists of `{prefix, key}` entries. Note that `notify:` and
`primaries:` are *not* ACLs — they are lists of destinations and sources, and
take `{addr, key}` entries where the address includes a port. Writing `addr:`
inside a `downstreams:` entry is the single most common mistake; it decodes to
an empty prefix and quarantines the zone with `bad ip-spec ""`.

### The prefix field

`prefix` is an ip-spec matched against the **source address** of the request:

| Form | IPv4 | IPv6 |
|------|------|------|
| bare address | `192.0.2.1` | `::1` |
| CIDR | `192.0.2.0/24` | `2001:db8::/32` |
| netmask | `192.0.2.0&255.255.255.0` | — |
| range | `192.0.2.10-192.0.2.20` | `2001:db8::10-2001:db8::20` |
| any | `0.0.0.0/0` | `::/0` |

`0.0.0.0/0` matches IPv4 sources only and `::/0` matches IPv6 sources only. To
allow both address families you need both entries — this catches people out on
dual-stack servers.

### The key field

`key` says what the matched source must present:

- **a TSIG key name** — the request must carry a valid TSIG signed with that key.
- **`NOKEY`** — the source is trusted by address alone. Unsigned requests are
  accepted, and a TSIG that happens to be present is not enforced.
- **`BLOCKED`** — deny. A matching `BLOCKED` entry supersedes every allow entry
  in the list, wherever it appears (NSD semantics).

### How matching works

Matching collects **every** non-`BLOCKED` entry whose prefix matches the source,
and the request is accepted if it satisfies **any one** of the collected keys.
Two consequences follow, and both are load-bearing.

**A `NOKEY` entry disables TSIG enforcement for every source it covers.** If
one entry names a key and a broader entry says `NOKEY`, a source matching both
is accepted unsigned. The `NOKEY` is checked first and wins:

```yaml
downstreams:
   - prefix: "192.0.2.0/24"
     key:    xfr-key-2026     # intended: TSIG required
   - prefix: "0.0.0.0/0"
     key:    NOKEY            # ...but this makes it optional for 192.0.2.0/24 too
```

If you want TSIG enforced, do not leave a `NOKEY` entry covering the same
addresses.

**Two named keys for one source accept either.** This is how you roll a TSIG key
without downtime: add the new key alongside the old, migrate the secondary, then
drop the old entry.

```yaml
downstreams:
   - prefix: "2001:db8:1::/48"
     key:    xfr-key-2026     # new key
   - prefix: "2001:db8:1::/48"
     key:    xfr-key-2025     # old key, still accepted during the overlap
   - prefix: "192.0.2.66"
     key:    BLOCKED          # denied even with a valid key
```

## Zone declarations

A zone is one entry in the top-level `zones:` list.

| Key | Type | Notes |
|-----|------|-------|
| `name` | string | **required**, FQDN with trailing dot |
| `type` | string | **required** unless inherited from a template: `primary` or `secondary` |
| `zonefile` | path | required for primary; optional persistence for secondary |
| `store` | string | `map` (default) or `xfr` |
| `template` | string | name of an entry in `templates:` |
| `primaries` | list of `{addr, key}` | required for `secondary` |
| `notify` | list of `{addr, key}` | NOTIFY destinations |
| `allow-notify` | list of `{prefix, key}` | inbound-NOTIFY ACL |
| `downstreams` | list of `{prefix, key}` | provide-xfr ACL |
| `options` | list of strings | see below |
| `dnssecpolicy` | string | names an entry in `dnssec.policies:`; `none` == unset |
| `multisigner` | string | names an entry in `multisigner:` |
| `updatepolicy` | block | DNS UPDATE authorization |
| `delegationbackend` | string | required if the zone accepts child updates |

Note the spellings: **`dnssecpolicy`** and **`multisigner`**, each one word.
`dnssec_policy`, `dnssec-policy` and `multi_signer` are not config keys; they
decode to nothing and leave the zone without a policy, which then makes
`online-signing` fail validation.

### store

Only two values are live. `map` is the general-purpose store and the default.
`xfr` holds the zone for transfer in and out only — it does **not** answer
normal queries. `slice` is deprecated: it logs a warning and falls back to
`map`. Any other value, including the `reg` mentioned in some older comments,
also falls back to `map`.

### Zone options

`options:` is a list of strings. An unrecognized option puts the zone in `ERROR`
state with `unknown config option: "..."`.

**Delegation synchronization**

| Option | Effect |
|--------|--------|
| `delegation-sync-parent` | Provide delegation sync toward child zones (accept child DS/NS/A/AAAA updates) |
| `delegation-sync-child` | Push this zone's DS/NS/A/AAAA changes to its parent |
| `delegation-sync-proxy` | Agent secondary proxies CDS/CSYNC NOTIFYs upstream for a DSYNC-unaware primary |

**Zone modification**

| Option | Effect |
|--------|--------|
| `allow-updates` | Accept authenticated DNS UPDATE for any RRset |
| `allow-child-updates` | Accept DNS UPDATE of child delegation data only. Forced off when the child update-policy type is `none` or unset; the zone must also set `delegationbackend:` |
| `allow-edits` | Allow apex RRsets (NS, DNSKEY, CDS, CSYNC) to be modified dynamically |

**DNSSEC**

| Option | Effect |
|--------|--------|
| `online-signing` | Sign responses on the fly |
| `inline-signing` | Maintain a signed copy of the zone |
| `dont-publish-key` | Do not publish the zone's SIG(0) KEY record |

Both signing options **require the zone to set `dnssecpolicy:`**. Without one,
the option is dropped and the zone goes to `ERROR` with "... is ignored because
the DNSSEC policy is not set". Neither is accepted by `tdns-agent`, which does
not sign.

**DNS behaviour**

| Option | Effect |
|--------|--------|
| `fold-case` | Case-insensitive owner-name matching |
| `black-lies` | Compact denial of existence: synthesize a minimally covering NSEC rather than serving precomputed NSEC records |
| `add-transport-signal` | Synthesize SVCB transport-signal RRs into the Additional section |

**Multi-provider and catalog**

| Option | Effect |
|--------|--------|
| `multi-provider` | Zone is served by several providers (RFC 8901); changes signing and rollover behaviour |
| `catalog-zone` | RFC 9432 catalog zone. Requires a `catalog:` config section |
| `catalog-member-auto-create` | Auto-create member zones from this catalog. Only valid on a zone that also has `catalog-zone` |
| `catalog-member-auto-delete` | Auto-delete member zones removed from this catalog. Same requirement |

**Options you cannot set.** `dirty`, `frozen`, `automatic-zone`,
`api-managed-zone`, `multi-signer` and `dont-publish-jwk` are real zone options,
but the server sets them itself. Putting any of them in `options:` is rejected
as an unknown option. You will see them in `tdns-cli auth zone list` output.

## Zone templates

Templates are declared in the top-level `templates:` list. A template is an
ordinary zone declaration that carries a `name:` and is not itself served, so it
accepts every key a zone accepts.

```yaml
templates:
   - name:          signed-primary
     type:          primary
     store:         map
     options:       [ delegation-sync-parent, online-signing ]
     dnssecpolicy:  default
     downstreams:
        - prefix: "192.0.2.0/24"
          key:    NOKEY

zones:
   - name:      example.com.
     zonefile:  /etc/tdns/zones/example.com.zone
     template:  signed-primary       # type, store, options, policy, ACL inherited
```

`templates:` is a **list**, not a map keyed by template name. A mapping shape
fails the whole config load with `'templates': source data must be an array or
slice, got map`. A zone naming a template that does not exist is quarantined
with `template "..." does not exist`.

The merge is a **gap fill**: the zone's own value always wins, and the template
supplies only what the zone left unset. Four rules qualify that.

1. **`options:` is a union, not a gap fill.** Template options are appended to
   the zone's list. A zone can add options but cannot remove one the template
   supplies.

2. **`zonefile:` in a template is a `fmt.Sprintf` pattern**, `%`-substituted
   with the zone name — which includes its trailing dot. So
   `zonefile: /etc/tdns/zones/%szone` yields
   `/etc/tdns/zones/example.com.zone` for zone `example.com.`. A pattern that
   expands to a path containing `..` is rejected.

3. **`dnssecpolicy:` is gap-filled for tdns-auth but never for tdns-agent**,
   which does not sign.

4. **A field counts as "set" only if it is non-zero.** A zone therefore cannot
   override a template value back to an empty or zero value. If a template says
   `store: xfr`, a zone cannot revert to the default by writing `store: ""` —
   it must name the other value explicitly. The same applies to any `false`
   the template set to `true`.

`name:` and `template:` are never copied from a template. A template may itself
set `template:` to inherit from another; cycles are detected and rejected.

## The dnsengine block

```yaml
dnsengine:
   addresses:   [ 127.0.0.1:5354, '[::1]:5354' ]
   transports:  [ do53, dot, doh, doq ]
   ports:
      dot:   [ 853 ]
      doh:   [ 443 ]
      doq:   [ 853 ]
   certfile:  /etc/tdns/certs/server.crt
   keyfile:   /etc/tdns/certs/server.key
   outbound_soa_serial:  keep
   options:
      - minimal-responses
```

| Key | Default | Meaning |
|-----|---------|---------|
| `addresses` | — | **required**. Do53 listen sockets, each `addr:port`. The host part is reused for the encrypted transports |
| `transports` | — | **required**. Any of `do53`, `dot`, `doh`, `doq`. `do53` is added even if omitted |
| `certfile` / `keyfile` | — | required for `dot`/`doh`/`doq`; if absent those listeners do not start |
| `ports.dot` | `853` | listen ports for DoT |
| `ports.doh` | `443` | listen ports for DoH |
| `ports.doq` | `853` | listen ports for DoQ (only 853 is truly supported) |
| `outbound_soa_serial` | `keep` | `keep`, `unixtime` or `persist` |
| `options` | — | server-wide options, below |

`ports.do53` is **not read**. Do53 always listens on the ports embedded in
`addresses`.

`outbound_soa_serial` controls the SOA serial advertised to secondaries.
`keep` sends the inbound serial unchanged. `unixtime` uses the load time.
`persist` remembers the last serial in the database, so a restart with no zone
change does not regress the serial and does not provoke a needless AXFR — the
right choice for a primary with BIND/Knot/NSD secondaries.

Two `options:` values are recognized:

- **`minimal-responses`** — omit the authority NS RRset and apex glue from
  positive answers, BIND-style. Referrals and NXDOMAIN/NODATA are unaffected.
  Absence means false; `minimal-responses:false` disables it explicitly.
- **`parent-update:delta`** or **`parent-update:replace`** — how delegation
  updates are applied to the parent. `delta` is the default and applies even
  when no `options:` block is present.

## DNSSEC policies

All DNSSEC configuration lives under one top-level `dnssec:` block with six
sub-keys: `completeness`, `large_algorithms`, `split_algorithms`, `templates`,
`policies` and `kasp`.

A zone selects one policy by name with `dnssecpolicy: <name>`. If the config
defines no policies at all, a built-in `default` policy is injected (ED25519,
`ksk-zsk` mode, `forever` key lifetimes, no rollover).

### Policy keys

```yaml
dnssec:
   policies:
      example:
         algorithm:  ED25519       # default algorithm for both roles
         mode:       ksk-zsk       # ksk-zsk (default) | csk
         ksk:
            algorithm:  ED25519    # optional per-role override
            lifetime:   90d
         zsk:
            lifetime:   30d
         csk:
            lifetime:   none
         sigvalidity:              # per-RRTYPE, not per key role
            default:  14d          # REQUIRED, must be > 0
            dnskey:   30d          # defaults to `default`
            ds:       14d          # defaults to `default`
         rollover:
            method:        multi-ds       # none (default) | multi-ds | double-signature
            num-ds:        3
            parent-agent:  127.0.0.1:5354 # required when method != none
         ttls:
            dnskey:      2h
            # max_served: 5m
         clamping:
            enabled:  true
            margin:   1h           # REQUIRED when enabled
```

`sigvalidity` is a **policy-level block keyed by RRtype**, with `default`
required. It is not a per-key-role setting: there is no `sigvalidity` under
`ksk:` or `zsk:`, and those sub-blocks carry only `lifetime` and `algorithm`.

Durations accept Go duration strings plus a `d` (days) or `w` (weeks) suffix on
a plain integer: `14d`, `2w`, `90m`. Key lifetimes additionally accept
`forever` and `none`.

### Policy templates

`dnssec.templates:` holds partial policies. A policy sets `template: <name>` to
inherit the fields it does not specify itself.

```yaml
dnssec:
   templates:
      base:
         algorithm:  ED25519
         sigvalidity:
            default:  14d
            dnskey:   30d
         rollover:
            method:        multi-ds
            num-ds:        3
            parent-agent:  127.0.0.1:5354
   policies:
      from-template:
         template:  base
         ksk:
            lifetime:  90d
         zsk:
            lifetime:  30d
```

Unlike the *zone* template merge, which is shallow, the policy merge is a
**deep** merge: a policy that sets only some leaves of a nested block (`ksk`,
`zsk`, `rollover`, `ttls`, `sigvalidity`, `clamping`) inherits the remaining
leaves of that block from the template. The policy's own values always win.

The same zero-value caveat applies: a policy cannot override a template value
back to `""`, `0` or `false`, because those read as "unset". A template that
sets `clamping.enabled: true` cannot be switched off by a policy that inherits
from it.

Templates are not usable policies. A zone cannot reference one, and an unknown
template name quarantines just that policy.

### split_algorithms

A policy whose KSK and ZSK algorithms differ is **rejected at config load**
unless that exact pair is allowlisted. This fails closed, so an accidental
mismatch is caught rather than silently deployed.

```yaml
dnssec:
   split_algorithms:
      RSASHA512: [ ED25519, ECDSAP256SHA256 ]
```

The map is keyed by **KSK** algorithm name; the value lists the ZSK algorithms
that KSK may pair with. Policies using the same algorithm for both roles always
work and need no entry. An algorithm name this binary does not know is skipped
with a warning — which means the pair it would have permitted stays forbidden.

### large_algorithms

Algorithms whose DNSKEY and RRSIG payloads are large for UDP.

```yaml
dnssec:
   large_algorithms: [ RSASHA512, MLDSA87, FALCON1024 ]
```

Listing an algorithm here makes the internal resolver fetch a child zone's
DNSKEY over TCP from the outset — rather than trying UDP and retrying on
truncation — whenever a referral's DS RRset uses it, and makes the signer emit
bulk-signing warnings. Entries are algorithm **names**, not codepoints, because
the non-standardized PQ codepoints are assigned per deployment.

Names must match **exactly** (case-insensitively); an unknown name is a hard
config error and the server refuses to start. The accepted post-quantum
spellings are compact and uppercase — `MLDSA44`, `MLDSA65`, `MLDSA87`,
`SLHDSA128S`, `FALCON512`, `FALCON1024`, `MAYO1`, `MAYO2`, `MAYO3`, `MAYO5`,
`SNOVA24_5_4`, `SNOVA37_17_2`, `SNOVA25_8_3`, `SQISIGN1`, `QRUOV_Q31_L3`,
`CROSSRSDPG128SMALL` — not the hyphenated spec forms (`ML-DSA-44`).

> Name-prefix globs such as `MLDSA*` are **not** supported on this branch; they
> are a hard "unknown algorithm" error. Prefix matching against the algorithm
> metadata registry is implemented on `feature/large-alg-prefix-matching` and
> this section will be updated when that lands.

Which PQ names resolve depends on how the binary was built — an algorithm needs
a real, linked implementation, not merely registered metadata.

### completeness and kasp

`dnssec.completeness:` is deployment-wide and takes `strict` (default) or
`relaxed`. It governs whether a ZSK algorithm rollover keeps the old-algorithm
key signing through the drain window. An unknown value is a hard config error.

`dnssec.kasp:` configures the key-state worker:

| Key | Default |
|-----|---------|
| `propagation_delay` | `1h` |
| `check_interval` | `1m` |
| `standby_zsk_count` | `1` |
| `standby_ksk_count` | `0` |

For the rollover machinery these policies drive, see
[Automatic DNSSEC Rollovers](key-rollover.md) and
[Rollover Timing Equations](rollover-timing-equations.md).
