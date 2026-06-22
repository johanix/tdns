# Operator guide: tdns-agent as a DSYNC proxy

This describes how to run tdns-agent as a SECONDARY that forwards
delegation-sync to the parent on behalf of a primary that is DSYNC-unaware
(BIND9, Knot, NSD, etc.). The agent forwards via whichever scheme the
parent advertises: a generalized NOTIFY (the parent re-scans the child), or
a signed DNS UPDATE (the agent sends the delegation records directly).

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

- The PARENT publishes a DSYNC RRset (e.g. tdns-auth with
  `delegation-sync-parent`). The proxy uses whichever scheme it advertises:
  NOTIFY (for CDS/CSYNC) and/or UPDATE. When both are advertised, UPDATE is
  preferred (it lands the change in one round-trip and works for unsigned
  zones).
- For the NOTIFY scheme: the PRIMARY publishes CDS/CDNSKEY and/or CSYNC when
  it wants the parent updated (its own tooling). For the UPDATE scheme: the
  agent needs a SIG(0) key the parent trusts (see "UPDATE proxy" below).
- The AGENT is a secondary for the zone (transfers it from the primary)
  and can reach the parent's advertised target.


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
- For the NOTIFY scheme no SIG(0) key is needed (a NOTIFY is a contentless
  "come re-scan me" signal). The UPDATE scheme DOES need a SIG(0) key — the
  agent generates it and you publish its public KEY at the primary (see
  "UPDATE proxy" below). The agent never authors anything else in the zone.
- The UPDATE form is REPLACE by default (delete the RRset, re-add the
  current members — idempotent and self-correcting). To use delta instead,
  set the `parent-update: delta` auth option under `dnsengine.options`.


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


## UPDATE proxy (parent advertises DSYNC UPDATE)

When the parent advertises the UPDATE scheme, the agent can send the
delegation records (NS + glue + DS) to the parent directly in a signed DNS
UPDATE, rather than asking it to re-scan. This is preferred over NOTIFY
when available, and — unlike NOTIFY — it works for an UNSIGNED zone too
(there is no CDS/CSYNC to scan, but the NS/glue can still be synced).

The parent must trust the UPDATE. It does so by the SIG(0) key that signs
it: the agent signs AS the child, with a key whose public KEY is published
at the child apex (exactly how a DSYNC-native child is trusted). Since the
agent is only a secondary, it cannot publish that KEY itself — you publish
it once at the primary.

**Bootstrap, step by step:**

1. Enable `delegation-sync-proxy` on the zone (above) and start/reload the
   agent. If the parent advertises UPDATE and no KEY is published yet, the
   agent generates a SIG(0) keypair and records a warning on the zone.
2. Ask the agent what to publish:

   ```
   tdns-cli ... zone proxy-key -z child.example.
   ```

   In the waiting state this prints two records to add at the primary apex:
   the agent's **KEY** RR, and an **HSYNCPARAM** record with the `pubkey`
   flag. (The `pubkey` flag tells every provider of the zone to republish
   the apex KEY — so the bootstrap works even with multiple providers.)
3. Add those two records to the zone at the primary. They transfer in to the
   agent on the next refresh.
4. Once the agent sees its KEY at the apex, `proxy-key` reports READY and the
   agent starts proxying UPDATEs.

`proxy-key` reports one of four states: `update-unsupported` (parent
advertises no UPDATE — use NOTIFY), `waiting` (publish the printed records),
`ready` (operating), or `foreign-key` (a KEY the agent does not own occupies
the apex — remove it, or UPDATE-proxy cannot work; NOTIFY may still apply).

On startup the agent also does a one-time parent-vs-child reconcile: if the
delegation drifted while the agent was down, it sends one UPDATE to fix it
— but it does NOT re-send on every restart when nothing changed.


## Limitations

- The agent must be able to reach the parent's advertised target.
- UPDATE-proxy for a zone served by multiple providers relies on the
  HSYNCPARAM `pubkey` flag to get the agent's KEY published across all
  providers; the primary must support adding that record.
- A `foreign-key` state (a KEY at the apex the agent does not own) disables
  the UPDATE proxy for that zone until resolved; NOTIFY may still apply.


## Verifying

- Change the CDS (or CSYNC, or NS/glue) at the primary, let the agent
  transfer the zone, and watch the agent log for either
  `delegation-sync-proxy: forwarded NOTIFY(...) to parent` (NOTIFY scheme)
  or `proxied ... UPDATE to parent ... (rcode NOERROR)` (UPDATE scheme).
- For the NOTIFY scheme on a tdns-auth parent, the incoming NOTIFY routes to
  the scanner (`CheckCDS` / `ProcessCSYNCNotify`), which queries the child
  and applies the change. For the UPDATE scheme the parent applies the
  records directly after validating the SIG(0) signature.
- `tdns-cli ... zone proxy-key -z <zone>` reports the current UPDATE-proxy
  state at any time.
