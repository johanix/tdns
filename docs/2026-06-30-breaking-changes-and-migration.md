# Breaking changes & migration guide — replication / config stack (2026-06-30)

**Audience:** operators upgrading from `main` to the stacked branches
(`dynamic-zones-mgmt` → `tsig-on-replication` → `feat/tsig-first-class`).

These are **behavior and config-format changes that affect existing deployments even if
you use none of the new features** (dynamic zones, catalog zones, TSIG, multi-primary).
They were found by a focused "features-off" regression review; the rest of the system
(DNSSEC key rollovers, SIG(0), config reload, query serving, caching, normal secondary
refresh) is unchanged — see §5.

---

## 1. Outbound zone transfers (AXFR/IXFR) are no longer open by default — **action required**

**What changed.** On `main`, serving AXFR/IXFR to secondaries was unrestricted — any
client that could reach the port could transfer a zone. Now `ZoneTransferOut` is gated
by a per-zone **`downstreams:` allow-transfer ACL, and an empty/absent ACL DENIES all
transfers.**

**Why.** This closes the legacy open-AXFR default; open AXFR allows anyone to enumerate
full zone contents. (Deliberate security change.)

**Impact if you do nothing.** Every secondary that pulls AXFR/IXFR from this server is
**REFUSED** — there is no error on the serving side beyond a log line, so secondaries
silently go stale and a freshly-started secondary with no cached zone has no data.

**Migration.** For each zone this server serves transfers for, add a `downstreams:` ACL
listing each secondary (IP, CIDR, or range) with `key: NOKEY` for unsigned transfers (or
a named TSIG key to *require* signing):

```yaml
zones:
  example.com:
    # …
    downstreams:
      - { prefix: 192.0.2.2,    key: NOKEY }   # secondary ns2 (unsigned)
      - { prefix: 192.0.2.0/24, key: NOKEY }   # a whole network
      - { prefix: 2001:db8::/32, key: NOKEY }
```

`prefix` is an ip-spec: a bare IP, CIDR, mask, or `lo-hi` range. `key: NOKEY` means "no
TSIG required from this source." `key: BLOCKED` explicitly denies (supersedes allows).

## 2. Inbound NOTIFY is now source-authorized (mostly preserved)

**What changed.** `NotifyResponder` now authorizes the NOTIFY source. With **no
`allow-notify:` configured (the default), a NOTIFY is accepted only from the zone's
configured primaries** (unsigned is fine).

**Impact.** A normal secondary that only expects NOTIFY from its primary is **unchanged**.
A NOTIFY from a host that is *not* one of the zone's primaries — which `main` would have
accepted and acted on — is now refused.

**Migration.** Usually nothing. If you relied on accepting NOTIFY from a host outside the
primaries list, add it to `allow-notify:` (same `{ prefix, key }` form as `downstreams`).

## 3. Peer/ACL config fields migrated to structured entries — **action required**

The replication config fields changed shape (NSD-aligned); **bare-string lists no longer
parse.** Peers you talk to use `{ addr, key }`; ACLs you match inbound sources against use
`{ prefix, key }`:

| field | role | old form | new form |
|---|---|---|---|
| `primaries:` | secondary: who we pull from | `primary: "192.0.2.1"` | `[{ addr: 192.0.2.1, key: NOKEY }]` |
| `notify:` | primary: who we send NOTIFY to | `notify: [192.0.2.2]` | `[{ addr: 192.0.2.2, key: NOKEY }]` |
| `allow-notify:` | secondary: who may NOTIFY us | (n/a) | `[{ prefix: 192.0.2.1, key: NOKEY }]` |
| `downstreams:` | primary: who may AXFR from us (§1) | `downstreams: [192.0.2.2]` (was a notify list) | `[{ prefix: 192.0.2.2, key: NOKEY }]` |

```yaml
    primaries:
      - { addr: 192.0.2.1, key: NOKEY }
    notify:
      - { addr: 192.0.2.2, key: NOKEY }
```

**Failure modes if not migrated:**
- A legacy bare-string **`notify:`** quarantines *that zone* (it lands in `broken_zones`)
  until rewritten.
- A legacy bare-string **`downstreams:`** currently fails the *whole* config load.
  *(This is being softened to a per-zone quarantine like `notify`.)*

> Note: `downstreams:` also changed *meaning* — on `main` it was the NOTIFY target list;
> it is now the allow-transfer ACL (§1). NOTIFY targets are now `notify:`. Do not assume an
> old `downstreams:` list carries over as your NOTIFY set.

## 4. Hostname primaries are resolved via the built-in resolver (IMR)

A primary given as a **hostname** (not an IP) is resolved using tdns's internal resolver,
which is **active by default**. If you run with `imr.active: false`, hostname primaries
cannot be resolved — use IP addresses, or keep the IMR active.

> Known issue being fixed: a hostname-primary lookup is currently attempted once at
> startup, and a transient failure leaves the zone in a permanent error state. Resolution
> is being changed to **retry on the refresh schedule** so a transient DNS failure
> self-heals. Until that lands, prefer IP-address primaries if startup-time resolver
> availability is uncertain.

## 5. No action needed — confirmed unchanged

A classic deployment using none of the new features sees **no change** in:
- **DNSSEC key rollovers and SIG(0)** — the shared KeyDB transaction layer and
  `/keystore` handler are behaviorally identical for sig0/dnssec; the added transaction
  locking and commit-error reporting are pure hardening (and fix a latent
  "stuck-transaction-after-failed-Begin" bug).
- **Config reload** of a non-TSIG config (no-ops cleanly), **DB schema** (additive table
  only, no migration of existing tables), **query serving / EDNS / caching / the
  resolver**, **catalog code** (fully gated off), and **normal single-primary secondary
  refresh** (SOA probe / AXFR / retry-expire timing identical).
