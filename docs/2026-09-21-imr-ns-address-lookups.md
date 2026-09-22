# IMR: one address lookup per nameserver name

**Date:** 2026-09-21
**Status:** implemented in the PR that adds this document
**Follows:** #683 (#675) and #693 (#682)

## Problem

A zone whose nameservers are all out-of-bailiwick (Azure DNS, Route 53 and the like) arrives from its parent with no glue. #693 resolves those nameservers' addresses and stores the servers in the zone's cached server map, so that later queries find them. The first query into the zone still has to look the addresses up. Four places did that, each with its own queries:

| Path | Before |
|---|---|
| `handleReferral` → `resolveZoneServersInBackground` | background lookup, one per name (#693's `nsAddrLookups`) |
| `IterativeDNSQuery` → `expandServerMapWithMissingNS` | its own A then AAAA per missing name, one name after another |
| `ImrResponder` / `ImrQuery` → `resolveNSAddresses` → `CollectNSAddresses` | its own A and AAAA for every name, on the query's context |

The referral starts the background lookup and returns with an empty server map. The caller then falls straight into one of the fallbacks, which sends the same queries again. A loopback test measured two A queries for one nameserver where there should be one. The fallback also queried nameservers whose shared `AuthServer` already had addresses.

## Design

### `nsLookup(ctx, nsname, zone) <-chan struct{}`

This function starts the address lookup for `nsname`, or joins the one already running. It registers `zone` to receive the server once the server has an address. It never waits: the channel it returns is closed when the lookup has ended and the server has been stored.

- **Detached.** The lookup runs on `detachedContext`. A caller that stops waiting (its context ends) leaves the lookup running, and the result is still stored in every registered zone's map.
- **One per name.** `nsAddrLookups` maps each nameserver name to its running lookup: a `done` channel and the set of registered zones. `begin` returns the running lookup or creates one; `join` registers a zone with a running lookup and never creates one; `end` removes it and returns the zones.
- **A and AAAA at once.** `lookupServerAddrs` sends the two queries concurrently. Each `ImrQuery` is bounded by one query budget, so a lookup takes at most about one budget; the context's deadline of twice the budget is only an outer cap.

### Callers

- `resolveZoneServersInBackground` calls `nsLookup` for each chosen name and does not wait.
- `expandServerMapWithMissingNS` counts a missing name whose shared server already has addresses, with no query. It calls `nsLookup` for every other missing name, then waits for all of them, bounded by its context.
- `resolveNSAddresses` does the same for every nameserver of the zone. It hands each server to `onResponse` as soon as that server's lookup ends with an address.
- `CollectNSAddresses` and `processAddressRecords` have no callers left and are removed.

### A lookup that needs its own name

Resolving `ns1.example.` can start at `example.`, and `example.` can be served by `ns1.example.` itself (a nameserver without glue) or by a zone whose nameservers are named in `example.` (a cycle). The lookup's own walk then reaches a fallback for the same name. Joining the running lookup would wait on itself until the deadline.

To prevent this, a lookup's context carries the chain of nameserver names it is nested in (`nsLookupChainKey`). This is the one value put on a detached context, and it is put there on purpose. `nsLookup` starts nothing for a name already on the chain and returns a closed channel. In the test with a glueless in-bailiwick nameserver, the fallback returns at once; without the check it waited the full 16 s deadline.

It does register the zone it was called for with the running lookup (`join`). The walk may meet a referral to a second zone that names the same nameserver; that zone then gets the server when the running lookup ends, as a zone registered by an independent caller does.

Two lookups started independently can still wait on each other in a cycle. Those waits end when each lookup's own queries run out of budget. That is no worse than before, when the recursion also ran until the budget, and such a delegation has no address to find anyway.

## Tests

`v2/imr_ns_lookup_join_test.go`, against the loopback auth double of `imr_oob_servers_stored_test.go`:

| Test | Before this change |
|---|---|
| a referral, then `expandServerMapWithMissingNS`, sends one A query | 2 queries |
| a referral, then `resolveNSAddresses`, sends one A query | 2 queries |
| a shared server that already has addresses costs no query | 1 query |
| a waiter that gives up still leaves the server stored | never stored |
| a lookup needing its own name ends at once | 16 s (with the chain check disabled) |
| two zones naming one nameserver share one lookup, and both get the server | passed; covers the waiting-zones set |
| a nested call for a name on its own chain returns at once and still registers its zone | the second zone never got the server |
