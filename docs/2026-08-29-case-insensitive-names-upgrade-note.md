# Upgrade note: DNS names are folded by the DNS rule (2026-08-29)

**Audience:** operators upgrading past the case-insensitive name series
(#416–#425).

**Short version: for almost every deployment there is nothing to do.** A zone
whose name and owner names are all lowercase — which is nearly all of them —
serves, sorts, signs and digests to exactly the same bytes as before. That was
measured, not assumed: see §5.

Three things can change, all of them for data that is mixed-case. §1 is the only
one that can fail silently, and the server now warns about it at startup.

---

## 1. A zone whose NAME is written in mixed case — **action recommended**

**What changed.** `zd.ZoneName` used to be folded only when the `fold-case` zone
option was set. That option defaults off and is set in neither shipped sample
config, so in practice zone names were kept exactly as written. They are now
always folded to their canonical form.

**Why.** Every index — the zone registry, the owner map, the published snapshot,
the working set — is keyed canonically, so a zone whose own name is not
canonical cannot find its own apex. Before this series, a zone declared
`Example.COM.` could not be reached by *any* query.

**Impact if you do nothing.** The zone now works. But two things keyed by the
zone name outside those indexes do not follow the fold:

- **Keystore rows written by an older tdns.** `OutgoingSerials`,
  `ZoneSigningState`, `RolloverKeyState`, `ZskRolloverState`,
  `RolloverZoneState` and `ZonePolicyOverride` hold rows under the spelling the
  older build used. A lookup for `example.com.` does not find a row stored under
  `Example.COM.`
- **The zone file path**, which is derived from the zone name. A file written by
  an older tdns under the config spelling is orphaned on a case-sensitive
  filesystem.

The sharp edge is `OutgoingSerials`. `LoadOutgoingSerial` treats "no row" as
"nothing has been served yet" rather than as an error — deliberately, because
that is the normal case for a zone that has never notified a secondary. After an
upgrade it is no longer the normal case. The zone can republish **below** a
serial a secondary already holds, and a secondary refreshes on a serial increase
and nothing else, so it serves the pre-upgrade zone indefinitely. Nothing is
logged.

**Migration.** Rename the zone to its canonical (lowercase) spelling in the
config. The server warns once per non-canonical zone name at startup and on
config reload:

```
WARN zone name is not canonical; keystore rows and zone files written by an
     older tdns under the configured spelling will not be found, and an unfound
     outgoing serial is silently treated as 'nothing served yet'
     configured=Example.COM. served_as=example.com.
```

If you have already run the new build against such a zone and secondaries have
gone quiet, the outgoing serial is the thing to check first.

---

## 2. A zone FILE containing owners spelled in mixed case — **expect one re-sign**

**What changed.** Records were previously dropped at load if the owner spelled
the *zone-name part* in a different case — `www.EXAMPLE.com.` in a zone
`example.com.` — with a log line and no error. `$ORIGIN EXAMPLE.com.` followed
by relative names produces exactly that. Those records are now kept.

**Impact if you do nothing.** Such a zone gains the records it was silently
losing. That is the fix working, but it means the zone's contents change on the
first load after upgrade: the serial bumps, the NSEC/NSEC3 chain is rebuilt, and
a signed zone re-signs. Secondaries transfer once.

**Migration.** None required. Expect one serial bump and one re-sign per affected
zone, and do not be alarmed by it.

---

## 3. Mixed-case queries are now answered — **no action**

Queries whose names differ in case from stored data now resolve. Before the
series this was inconsistent: whether a mixed-case query worked depended on
whether the *zone-suffix* part of the name happened to match the stored spelling
byte for byte. Notably, a resolver using 0x20 query-name randomisation could be
answered with a referral to the server's own apex.

Nothing to do. Mentioned because query logs may show names resolving that
previously did not.

---

## 4. Running the checks

The gate that keeps names folded correctly is a program, so `go vet` cannot run
it. From the repo root:

```
make check          # both gates: check-no-mutators and check-names
make check-all      # unit tests for every live module, then both gates
make check-names    # the name gate on its own
```

`check-all` is the one to run before a commit. It is not called `test` because
`utils/Makefile.common` defines that as the per-app `go test -v -cover` used by
the application directories.

---

## 5. What was measured, and what was not

**Measured.** A fingerprint over an ordinary all-lowercase zone — SOA, NS, MX,
CNAME, wildcard, delegation with glue, TLSA — covering the owner set, each
owner's stored spelling, its RRtype set, the canonical (NSEC chain) order and the
ZONEMD digest, is byte-identical before and after the series. The RFC 8976
Appendix A published test vectors also still pass, so the digest is unchanged
against an external reference and not merely self-consistent.

**Not measured.** Zones carrying names with octets that are not valid UTF-8.
Those are the case the series exists to handle correctly, and their behaviour
changes by design: two such names that previously collided onto one key now stay
distinct. If you have them, they were not working before.

**Not covered by the gate.** Byte-wise `==` comparison of names, which is how
[#427](https://github.com/johanix/tdns/issues/427) and
[#428](https://github.com/johanix/tdns/issues/428) survive. Both are
pre-existing, neither is introduced by this series, and neither will be reported
by `make check-names`. The full list of what the gate cannot see is in
[`2026-08-28-case-insensitive-names-scope.md`](2026-08-28-case-insensitive-names-scope.md).
