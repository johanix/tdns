# Operator guide: tdns-agent as a DSYNC proxy

This describes how to run tdns-agent as a SECONDARY that forwards
delegation-sync signals (NOTIFY(CDS)/NOTIFY(CSYNC)) to the parent on
behalf of a primary that is DSYNC-unaware (BIND9, Knot, NSD, etc.).

This proxy is one of the three delegation-sync roles; for how it fits with
the parent and self-syncing-child roles see
[Special Features §1.6](special-features.md). For the design rationale see
`../docs/2026-06-22-agent-dsync-proxy-for-clueless-primary-plan.md`.


## When to use this

Your zone's primary cannot speak DSYNC — it will never discover the
parent's DSYNC RRset, and it will never tell the parent to update the DS
or the delegation. But the primary CAN publish a CDS/CDNSKEY (RFC 7344)
and/or a CSYNC (RFC 7477) in the zone — that is the standard, vendor-
neutral way for a child to signal "please sync me."

Run tdns-agent as a secondary for that zone. On each incoming AXFR/IXFR it
watches for changes to the zone's CDS, CSYNC, NS+glue, or DNSKEY and, when
something changes, forwards the matching NOTIFY to the parent's DSYNC
NOTIFY receiver. The parent then re-scans the child and applies the change.
The primary stays exactly as it is.


## Requirements

- The PARENT publishes a DSYNC RRset advertising a NOTIFY scheme for CDS
  and/or CSYNC (e.g. tdns-auth as the parent does this with
  `delegation-sync-parent`). If the parent advertises only UPDATE, the
  proxy does nothing for now (UPDATE-proxy is later work).
- The PRIMARY publishes CDS/CDNSKEY and/or CSYNC when it wants the parent
  updated (this is the primary's own DNSSEC/delegation tooling — outside
  tdns).
- The AGENT is a secondary for the zone (transfers it from the primary)
  and can reach the parent's advertised NOTIFY target.


## Configuration

On the tdns-agent, configure the zone as a normal secondary and add the
`delegation-sync-proxy` option:

```yaml
zones:
   child.example.:
      type: secondary
      primary: 192.0.2.10:53        # the DSYNC-unaware BIND/Knot primary
      store: map
      options:
         - delegation-sync-proxy
```

Notes:

- `delegation-sync-proxy` is valid ONLY on a tdns-agent secondary zone. On
  any other app type, or on a primary zone, it is rejected with a config
  error (so a misconfiguration is loud, not silent).
- It is independent of `delegation-sync-child`. Use `delegation-sync-proxy`
  when the agent forwards on behalf of a clueless primary; use
  `delegation-sync-child` when the agent/auth IS the child syncing its own
  delegation.
- No SIG(0) key setup is needed for the proxy: a NOTIFY is a contentless
  "come re-scan me" signal — the agent never signs or authors anything in
  the zone.


## What triggers a NOTIFY

On each incoming transfer the agent diffs the new zone against the one it
was serving. The mapping from "what changed" to "what is forwarded":

| Change in the transfer            | NOTIFY sent to parent |
|-----------------------------------|-----------------------|
| CDS RRset changed                 | NOTIFY(CDS)           |
| DNSKEY RRset changed              | NOTIFY(CDS)           |
| CSYNC RRset changed               | NOTIFY(CSYNC)         |
| NS RRset or glue (A/AAAA) changed | NOTIFY(CSYNC)         |

The DNSKEY→NOTIFY(CDS) and NS/glue→NOTIFY(CSYNC) rows are intentional:
even if the primary changed keys or nameservers without (yet) republishing
the CDS/CSYNC, the agent nudges the parent to re-scan. A NOTIFY is cheap
and the parent decides for itself — it ignores a NOTIFY it has nothing to
do about.

Both can fire from one transfer (e.g. a CDS change and an NS change → both
NOTIFY(CDS) and NOTIFY(CSYNC)).


## What does NOT trigger a NOTIFY

- A bare SOA-serial bump with no change to CDS/CSYNC/NS/glue/DNSKEY. The
  trigger compares RRset CONTENT, not the serial.
- Re-transferring content the agent already forwarded. Because the agent
  diffs against what it is currently serving, a change fires exactly ONCE
  — on the transfer where it appears. A parent that is slow to absorb does
  NOT get re-NOTIFYd on every refresh; there is no NOTIFY storm.


## Limitations (first release)

- NOTIFY only. If the parent advertises only the UPDATE scheme, the proxy
  logs that it found no usable NOTIFY target and does nothing. (DNS-UPDATE
  proxying — which would also cover UNSIGNED zones — is planned later.)
- Signed zones only, in practice: CDS/CSYNC presuppose a signed zone, so an
  unsigned zone has nothing for the NOTIFY path to forward. (The option is
  NOT refused on an unsigned zone — that is deliberate, so the later
  UPDATE path, which works unsigned, is not foreclosed.)
- The agent must be able to reach the parent's advertised NOTIFY target.


## Verifying

- Change the CDS (or CSYNC) at the primary, let the agent transfer the
  zone, and watch the agent log for
  `delegation-sync-proxy: forwarded NOTIFY(...) to parent`.
- On a tdns-auth parent, the incoming NOTIFY routes to the scanner
  (`CheckCDS` / `ProcessCSYNCNotify`), which queries the child and applies
  the DS / delegation change.
