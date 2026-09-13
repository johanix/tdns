# tdns-imr returns the zone SOA in the ANSWER section on cached NODATA

**Status:** not filed yet. Found 2026-09-05 on the lab master.
**Resolvers compared:** `172.16.0.5` = unbound 1.25.1 (correct),
`172.16.0.7` = tdns-imr (buggy).

## The symptom that led here

Same query, two resolvers:

```
dog @172.16.0.5 _dsync.dnslab. DSYNC +algchase +dnssec   ->  Result: secure
dog @172.16.0.7 _dsync.dnslab. DSYNC +algchase +dnssec   ->  Result: indeterminate
```

Through imr, dog builds a four-level chain and treats `_dsync.dnslab.` as a
**zone** of its own:

```
. (root)              [secure]
  dnslab.             [secure]
    _dsync.dnslab.    [indeterminate]   "no DS record at parent"
      DSYNC RRset     [indeterminate]
```

Through unbound it correctly sees `_dsync.dnslab` as in-zone data and validates.

**This is not a dog bug.** dog asks `_dsync.dnslab. SOA` to locate the apex.
imr answers it with a SOA in the ANSWER section, so dog concludes the name is
an apex. Given that answer, dog's reasoning is correct.

## The actual defect

For **NODATA on a name that exists**, imr's cached response puts the zone's SOA
in the ANSWER section instead of the AUTHORITY section, and drops the AD flag.
The owner name of that SOA (`dnslab.`) does not match the qname
(`_dsync.dnslab.`).

The first, cold resolution is correct; every cache hit afterwards is wrong.
`ns1.dnslab SOA` against imr, three times in a row:

```
run 1:  flags: qr rd ra ad;  ANSWER: 0, AUTHORITY: 1     <- correct NODATA
run 2:  flags: qr rd ra;     ANSWER: 1, AUTHORITY: 0     <- bug
run 3:  flags: qr rd ra;     ANSWER: 1, AUTHORITY: 0     <- bug
```

and the wrong answer itself:

```
;; ANSWER SECTION:
dnslab.    900  IN  SOA    batman.dnslab. hostmaster.dnslab. 2026090631 ...
dnslab.    900  IN  RRSIG  SOA 15 1 900 ... 24954 dnslab. ...
```

unbound, same three names, every time: `ANSWER: 0, AUTHORITY: 1`, AD set.

### Scope

- Reproduces on every existing name tested: `_dsync.dnslab` (3/3),
  `master.dnslab`, `ns1.dnslab`. Not specific to underscore names or to DSYNC.
- **NXDOMAIN is not affected.** A never-queried, nonexistent name
  (`probe-<rand>.dnslab`) returns `ANSWER: 0` with AD set on every repeat.
  So the defect is in the NODATA path, not the negative path generally.
- The authoritative server is innocent: queried directly, and via unbound, the
  NODATA proof is correct (SOA+RRSIG and NSEC+RRSIG in AUTHORITY).

## Secondary imr findings, same session

1. **No EDNS OPT in many responses.** DO-bit queries come back with
   `ADDITIONAL: 0` and no OPT record (the DS, NS and SOA probes above). A
   response to an EDNS query must carry an OPT RR. `dig version.bind CH TXT`
   also produced `;; Warning: Message parser reports malformed message packet.`
   Inconsistent: the DNSKEY response *did* include OPT (udp 4096).

2. **Cached TTLs are not decremented.** imr returns the full authoritative TTL
   (900) on every repeat while the record is demonstrably cached — its SOA
   serial lagged the authoritative one (2026090637 vs 2026090638) at the same
   moment it reported TTL 900. unbound showed TTL 10 (lab cache cap) and the
   current serial. A downstream cache therefore re-arms to 900 s on every
   fetch, so the record's effective lifetime never expires.

3. **AD is lost on the buggy path** (see the run table above), so a validating
   stub behind imr sees these answers as unvalidated.

## Why it matters for the lab

`_dsync` is the delegation-sync discovery name. Any exercise that validates
DSYNC discovery through imr gets `indeterminate` where unbound gets `secure`,
and the natural conclusion for a student — and for me, earlier today — is that
the *zone* or *dog* is broken. It also silently changes what a validating
client behind imr sees for every NODATA answer in the lab.

---

## Amendment, 2026-09-08: filed and fixed

The status line above is stale, and was already stale about ninety minutes
after it was written.

This was filed the same evening as
[#518](https://github.com/johanix/tdns/issues/518) — "tdns-imr: cached NODATA
answers carry the zone SOA in the ANSWER section (plus missing OPT, and TTLs
that never decrement)", covering all three defects recorded here, not only the
first. It was **closed on 2026-09-05**.

Nothing above is corrected: it is the record of what was observed on the lab
master that day, and it is what the issue was written from. Read the status
line as "not filed *at the time of writing*".
