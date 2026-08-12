# IMR: a configured stub zone is unusable for ordinary resolution

**Date:** 2026-08-11
**Status:** OPEN. Reproduced on foffe, root cause not found.
**Severity:** blocks child-side delegation sync against any parent reached via a
stub — on every DSYNC scheme, not just the new API one.
**Contains:** the main problem (§1-5) plus three separate IMR issues found
alongside it (§6): an accessor aliasing asymmetry, a silent failure mode that
makes this class of bug hard to diagnose, and a sample config that does not
load. IMR issues are kept together here rather than filed apart.
**Found:** while trying to run the child half of the DSYNC API scheme end to end
(`2026-08-11-dsync-api-scheme.md` §17). Not caused by that work; it sits
underneath it.

---

## 1. Summary

`imrengine.stubs` registers, and the trust-anchor bootstrap uses it
successfully — it fetches and DNSSEC-validates the stub zone's DNSKEY RRset.
But **every ordinary query for a name in that zone makes zero auth-server
attempts and SERVFAILs**, with nothing logged even at `debug: true`.

The server map is present and correct at query time: `FindClosestKnownZone`
finds the zone and its server on every single lookup. The query simply never
happens.

---

## 2. Reproduction

A parent served by tdns-auth on `127.0.0.2:53` (signed, `inline-signing`,
policy `default`), and a child tdns-auth whose IMR reaches it only via a stub:

```yaml
imrengine:
   addresses:  [ 127.0.0.1:5396 ]
   transports: [ do53 ]
   debug: true
   verbose: true
   trust-anchor-file: /var/tmp/dsyncchild/trustanchor.txt   # the parent's KSK
   stubs:
      - zone:       dsynctest.example.
        servers:
           - name:   ns.dsynctest.example.
             addrs:  [ 127.0.0.2 ]
             alpn:   [ do53 ]
```

Then:

```
dig @127.0.0.1 -p 5396 dsynctest.example. SOA        →  SERVFAIL
dig @127.0.0.1 -p 5396 dsync-api.dsynctest.example. URI +dnssec  →  0 answers
```

while the parent answers those same questions directly:

```
dig @127.0.0.2 dsynctest.example. SOA                →  NOERROR, 1 answer
dig @127.0.0.2 dsync-api.dsynctest.example. URI      →  NOERROR, 1 answer
```

---

## 3. What works, and what does not

**Works** — the trust-anchor bootstrap, which reaches the stub via
`imr.Cache.ServerMap.Get(anchorName)` directly (`imrengine.go:1790`):

```
imrengine.go:238  adding stub zone=dsynctest.example. servers=ns.dsynctest.example. (127.0.0.2)
rrset_validate.go ValidateRRset: start: owner="dsynctest.example." type=DNSKEY sigs=1 rrs=3
imrengine.go:1717 cached DNSKEY zone=dsynctest.example. keyid=34645 trustAnchor=true
```

A DS query in the same phase is genuinely attempted — note `attempts=1`:

```
rrset_validate.go:926 backfillDS: no DS obtained for "dsynctest.example."
   (err=... 'dsynctest.example. DS' (zone=dsynctest.example. attempts=1
    last=ns.dsynctest.example.@127.0.0.2/do53)); leaving chain unanchored
```

That failure is correct in itself: a trust-anchor apex has no DS to find.

**Does not work** — the NS fetch immediately afterwards, in the same function,
passed *the same `serverMap` variable* (`imrengine.go:1835` →
`validateNSRRsetForAnchor`), reports **zero** attempts:

```
imrengine.go:1730 failed to fetch NS RRset for trust anchor zone zone=dsynctest.example.
   err=... 'dsynctest.example. NS' (zone=dsynctest.example., no auth-server attempts made)
```

`no auth-server attempts made` comes from `walkErr` when `attempts == 0`
(`dnslookup.go:1392`) — the server loop iterated zero times.

**And every ordinary query afterwards** behaves the same way. With
`imrengine.debug: true` the only thing logged per query is the server-map
lookup succeeding, three times, and then silence:

```
rrset_cache.go:894 FindClosestKnownZone: checking qname "dsynctest.example." against 1 zones with data in cache
rrset_cache.go:918 FindClosestKnownZone: authservers for zone "dsynctest.example.": ns.dsynctest.example.
   ... repeated 3x, then nothing at all. The client gets SERVFAIL.
```

So it is **not** a server-map lookup failure: the map is found, with the right
server, every time.

---

## 4. What has been ruled out

- **Key mismatch on the stub zone name.** `AddStub` stores under the config
  string verbatim (`ServerMap.Set(zone, ...)`, `rrset_cache.go:468`) and
  `FindClosestKnownZone` matches with `strings.HasSuffix`. Both use
  `dsynctest.example.` with the trailing dot, and the debug log confirms the
  match on every query.
- **An empty server map.** The same debug log names the server.
- **Missing transport.** Without `alpn: [ do53 ]` the entry decodes with no
  transports; adding it changed nothing. (`AddStub` also defaults to do53 when
  Alpn is empty, `rrset_cache.go:443`.)
- **Unreachable parent.** `dig @127.0.0.2` answers, and the DS query above
  reached it (`attempts=1 last=...@127.0.0.2/do53`).

---

## 5. Hypotheses worth checking

1. **The first query against a stub server poisons it for later queries.** The
   ordering fits exactly: DNSKEY succeeds, DS is attempted and legitimately
   finds nothing, and from then on nothing is ever attempted again. An address
   backoff (`AuthServer.AddressBackoffs`) or a transport-state update recorded
   on the empty DS answer would produce precisely this — `prioritizeServers`
   returning zero (server, addr, transport) tuples, hence `attempts == 0` with
   nothing to log.

2. **`IterativeDNSQuery` mutating the caller's map.** See issue B in §6 — the
   accessor asymmetry is a standing hazard whether or not it is this bug.

3. **`prioritizeServers` silently yielding nothing.** See issue C in §6.

---

## 6. Three separate issues found alongside this one

Kept here rather than filed apart, so the IMR problems stay together. All three
are worth fixing on their own terms, independently of whatever turns out to be
the root cause of §1.

### Issue B — `ServerMap.Get` hands out the stored map; `FindClosestKnownZone` copies

`processTrustAnchorZone` takes its server map with
`imr.Cache.ServerMap.Get(anchorName)` (`imrengine.go:1790`), which returns the
map **stored in the cache**. `FindClosestKnownZone` returns a shallow **copy**
(`rrset_cache.go:906-911`), with a comment saying why:

> Return a shallow copy of the map so concurrent callers don't race on writes
> (e.g. processAddressRecords adding resolved NS addresses).

So one accessor is guarded against exactly the hazard the other is wide open
to. Any callee that adds to or deletes from the map it was handed mutates the
cache in place through the first accessor and cannot through the second — and
`IterativeDNSQuery` does write into its `serverMap` argument
(`dnslookup.go:556,571,581,982,1644`). Whether or not this is the cause of §1,
two accessors for the same data with opposite aliasing rules is a footgun with
no upside. Either make `Get` copy too, or document the asymmetry at both ends.

### Issue C — a zero-tuple `prioritizeServers` result logs nothing

When `prioritizeServers` returns no (server, addr, transport) tuples, the
query loop simply never executes and the caller gets `attempts == 0`. Nothing
is logged, at any level, including `debug: true` — the only trace is the phrase
"no auth-server attempts made" in an error string, and only if someone happens
to surface that error.

A zero-tuple result is always a dead end for the query. It is never normal and
never recoverable, so it should say so: which zone, which servers were
considered, and why each produced nothing (no addresses / in backoff / no
usable transport / encryption required). **This is what turned §1 from a
five-minute diagnosis into an evening**, and it will do the same to the next
person.

### Issue D — the IMR sample config's stub form does not decode

`cmdv2/imr/tdns-imr.sample.yaml` documents:

```yaml
# stubs:
#    - zone:     internal.example.
#      servers:  [ 192.0.2.53, 2001:db8::53 ]
```

`ImrStubConf.Servers` is `[]cache.AuthServer` (`config.go:375-379`), so a bare
IP fails at config load with:

```
'imrengine.stubs[0].Servers[0]' expected a map, got 'string'
```

The daemon refuses to start. The working form is:

```yaml
stubs:
   - zone:       internal.example.
     servers:
        - name:   ns.internal.example.
          addrs:  [ 192.0.2.53, 2001:db8::53 ]
          alpn:   [ do53 ]
```

Either the sample or the decoder should change. A `StringToAuthServer` decode
hook would make the documented form work and is arguably the nicer config; the
one-line sample fix is the smaller change. Anyone copying the sample today gets
a daemon that will not start.

---

## 7. Impact

- Any child whose parent is reachable only via a stub cannot run delegation
  sync at all: `AnalyseZoneDelegation` fails before any scheme-specific code
  runs, so this hits NOTIFY, UPDATE and API alike.
- It blocks the child-side end-to-end test of the DSYNC API scheme
  (`2026-08-11-dsync-api-scheme.md` §17), which is otherwise ready to run: the
  parent signs, the trust anchor works, and the TLS/credential/policy path is
  verified live.
- Stubs are how a lab or a split-horizon deployment reaches a zone that is not
  in the public DNS, so this is not an exotic configuration.

---

## 8. Lab note from the same session

Not a bug in tdns, but it cost time and will again:

**`127.0.0.2` needs an explicit alias on NetBSD.** `inet 127.0.0.1/8` on lo0
does *not* make the rest of the /8 bindable, unlike Linux. Without

```
ifconfig lo0 alias 127.0.0.2 netmask 255.255.255.255
```

a listener on `127.0.0.2` fails with `bind: can't assign requested address` —
and, because the failure is per-listener rather than fatal, the daemon comes up
and answers on its other sockets while quietly serving no DNS at all.
