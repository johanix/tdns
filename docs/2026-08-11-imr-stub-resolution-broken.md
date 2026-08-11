# IMR: a configured stub zone is unusable for ordinary resolution

**Date:** 2026-08-11
**Status:** OPEN. Reproduced on foffe, root cause not found.
**Severity:** blocks child-side delegation sync against any parent reached via a
stub — on every DSYNC scheme, not just the new API one.
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

2. **`IterativeDNSQuery` mutating the caller's map.** `processTrustAnchorZone`
   obtains the map with `ServerMap.Get(anchorName)`, which returns the *stored*
   map rather than a copy — unlike `FindClosestKnownZone`, which explicitly
   copies (`rrset_cache.go:906-911`) with a comment about exactly this hazard.
   If any callee deletes from it, the cached stub entry is damaged in place.
   Less likely given §3 shows the entry still populated afterwards, but the
   asymmetry between the two accessors is real and worth closing regardless.

3. **`prioritizeServers` silently yielding nothing.** Whatever the cause, it
   produces no log line at debug level. A zero-tuple result is always a dead
   end for the query and should say so — that alone would have made this a
   five-minute diagnosis instead of an evening.

---

## 6. Impact

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

## 7. Two lab notes from the same session

Not bugs in the resolver, but both cost time:

- **`127.0.0.2` needs an explicit alias on NetBSD.** `inet 127.0.0.1/8` on lo0
  does *not* make the rest of the /8 bindable, unlike Linux; without
  `ifconfig lo0 alias 127.0.0.2 netmask 255.255.255.255` the listener fails
  with `bind: can't assign requested address`.
- **The IMR sample config's stub form does not decode.** It shows

  ```yaml
  # stubs:
  #    - zone:     internal.example.
  #      servers:  [ 192.0.2.53, 2001:db8::53 ]
  ```

  but `ImrStubConf.Servers` is `[]cache.AuthServer`, so a bare IP fails with
  `'imrengine.stubs[0].Servers[0]' expected a map, got 'string'`. The working
  form is `- name: ... / addrs: [ ... ] / alpn: [ do53 ]`. Either the sample or
  the decoder should change; the sample is the smaller fix.
