# Fix design: #484 + #506 - the child-side CSYNC publisher

Both bugs live in one 55-line file, `v2/ops_csync.go`, and both are in
`PublishCsyncRR`. They must ship together: fixing #484 alone makes things worse.

Not committed. Written 2026-09-05.

## The two bugs

**#484 - the immediate flag is never set.**

```go
func (zd *ZoneData) PublishCsyncRR() error {
	var flags uint16                      // declared, never assigned
	var csync = dns.CSYNC{
		Serial:     zd.CurrentSerial,
		Flags:      flags,                // therefore always 0
		TypeBitMap: typebitmap,
	}
```

The parent refuses it (`v2/scanner.go:837`):

```
ProcessCSYNCNotify: <child>: CSYNC does not have immediate flag set, only immediate updates are supported
```

So the NOTIFY/CSYNC scheme cannot complete between two tdns instances. Verified
end to end on the lab 2026-09-04: child published, parent scanned, all three
nameservers agreed on the CSYNC, and the parent stopped at the flag check.

**#506 - publish appends instead of replacing.**

```go
	csync.Hdr = dns.RR_Header{ Name: zd.ZoneName, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: 120 }
	zd.KeyDB.UpdateQ <- UpdateRequest{ Cmd: "ZONE-UPDATE", Actions: []dns.RR{&csync}, ... }
```

Nothing removes the CSYNC already at the apex, and each publish carries a
different `Serial` (`zd.CurrentSerial`), so the records are not duplicates and
the RRset grows by one per republish. Observed on the lab:

```
<child>.  120  IN  CSYNC  7 0 A NS AAAA
<child>.  120  IN  CSYNC  10 0 A NS AAAA
<child>.  120  IN  CSYNC  24 0 A NS AAAA
```

**Why they must ship together.** Today the parent rejects every CSYNC on the
flag check, so the accumulation is invisible - it never gets as far as mattering.
Fix #484 alone and the parent starts processing a child that publishes three
CSYNCs with three different serials, one of them now immediate. RFC 7477 sec 3 has
the parent act on "the CSYNC record" and consult its serial; with several there
is no defined answer, and the newest is indistinguishable from the stale ones
except by comparing serials, which the parent does not do. That is a worse
failure than the current clean refusal.

## What is already in place

- **The flag constants exist**: `csyncFlagImmediate uint16 = 0x01` and
  `csyncFlagSoaMinimum` (`v2/delegation_csync.go:55`). No new constant needed.
- **The parent already supports both flags**: `csyncFlags` parses them and
  refuses unknown ones (RFC 7477 sec 2.1.1.2), and `csyncSuppressedBySoaMinimum`
  implements the soaminimum serial gate. So soaminimum is a real option, not
  hypothetical.
- **RRset delete is already a supported action**: `dns.ClassANY` on a type means
  "remove RRset" in the zone updater (`v2/zone_updater.go:630`), and
  `UnpublishCsyncRR`, twelve lines below the bug, already builds exactly that
  record. The fix reuses it rather than inventing anything.

## The fix

**#484:** delete the unassigned variable and name the constant.

```go
	csync := dns.CSYNC{
		Serial:     zd.CurrentSerial,
		Flags:      csyncFlagImmediate,
		TypeBitMap: typebitmap,
	}
```

**#506:** send the delete and the add in one update, delete first.

Extract the anti-CSYNC record that `UnpublishCsyncRR` already builds into a
small helper, so both callers use one definition:

```go
// csyncDeleteRR returns the class-ANY record that removes the whole CSYNC
// RRset at zone's apex (RFC 2136 sec 2.5.2), so a publish replaces rather than
// appends.
func csyncDeleteRR(zone string) dns.RR {
	anti := &dns.CSYNC{TypeBitMap: csyncPublishedTypes}
	anti.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeCSYNC, Class: dns.ClassANY, Ttl: 0}
	return anti
}
```

then in `PublishCsyncRR`:

```go
	Actions: []dns.RR{csyncDeleteRR(zd.ZoneName), &csync},
```

and `UnpublishCsyncRR` becomes `Actions: []dns.RR{csyncDeleteRR(zd.ZoneName)}`.

The shared `typebitmap` (identical in both functions today) becomes one
package-level `csyncPublishedTypes` while we are here.

## LOC estimate

| Change | Files | Lines |
|---|---|---|
| #484: drop `var flags`, use `csyncFlagImmediate` | `v2/ops_csync.go` | -1 / +0, 1 modified |
| #506: `csyncDeleteRR` helper + shared type bitmap | `v2/ops_csync.go` | +10 |
| #506: use it in Publish and Unpublish | `v2/ops_csync.go` | 2 modified, -8 (the duplicated header block) |
| **Production total** | 1 file | **~15 lines net, one file** |
| Test: published CSYNC has the immediate flag | `v2/ops_csync_test.go` | +15 |
| Test: N republishes leave exactly one CSYNC | same | +30 |
| **Total** | 2 files | **~60 lines** |

No change to the parent side, no config surface, no API change, no migration.

## The one thing to verify while implementing

That a class-ANY delete and a class-INET add **of the same type, in one
UpdateRequest, are applied in order**. The zone updater supports both actions,
and the DSYNC API path already does delete-then-add for DS
(`CHILD-UPDATE DELETED[rrset]` followed by `CHILD-UPDATE ADDED` in one request,
seen on the lab 2026-09-04), so the pattern is established - but it is worth
confirming for CSYNC specifically rather than assuming. If ordering turns out
not to be guaranteed, the fallback is two sequential UpdateRequests, which costs
one extra serial bump per publish and is still correct.

Note also `ApplyZoneUpdateToZoneData` logs a warning when asked to delete an
RRset that is not there:

```
zone_updater.go:1026 [WARN/zones] ApplyZoneUpdateToZoneData: no RRset for owner owner=<child>. rrtype=CSYNC
```

That will now fire on every first publish. Either make the delete conditional on
an existing RRset, or drop that warning to debug - a delete-if-present is a
normal thing to ask for, not a warning-worthy event.

## Tests

1. **Flag**: publish, assert `Flags == csyncFlagImmediate`. The failure mode is
   a zero value that reads as deliberate, so this is worth pinning explicitly.
2. **Replacement**: publish three times with different serials, assert the apex
   holds exactly one CSYNC and that its serial is the newest. That test fails
   today and is the whole of #506.
3. **End to end, on the lab**: child publishes, parent applies rather than
   logging `CSYNC does not have immediate flag set`. This is the cell that
   failed in the 2026-09-04 matrix run (topology A / NOTIFY), so it doubles as
   the regression test for that.

## Decision: immediate only, or immediate + soaminimum?

Recommend **immediate only**.

soaminimum is implemented on the parent, and setting it would be harmless today
- the publisher sets `Serial: zd.CurrentSerial`, so the CSYNC serial equals the
child's SOA serial and `csyncSuppressedBySoaMinimum` (`c.Serial > soaSerial`) is
false. But it buys nothing at present and adds a suppression path that only
bites if serial handling later changes, which is a poor trade for a flag nobody
is asking for.

If the course later wants to demonstrate the soaminimum behaviour, that is the
moment to make it a policy value - and at that point it is a config key plus one
line here, not a redesign.
