# The publish cadence: what an operator sees

**Written 2026-10-01**, with step 4 of `2026-09-17-publish-gate-and-transactions.md`. Forty lines for the operator of a tdns-auth, tdns-agent or tdns-signer zone; the design has the reasons.

## One serial per cadence

Every change to a zone this server originates content for goes through one gate: a DNS UPDATE, a change through the management API, a child's delegation update, the DS engine's CDS, a signing pass, the catalog, the batch API tdns-mp uses. The gate's rule:

- A change to an **idle** zone, one that has not published within its cadence, is published at once, in the caller, as it always was.
- A change to a **busy** zone is staged and published at the last publish plus the cadence, together with everything staged by then: one serial, one journal delta, one IXFR link, one NOTIFY round.

The cadence is `publish-cadence` on the zone or its template, 5 seconds unless set. It was there before; what is new is that updates and the signing passes honour it, where each used to be a serial of its own.

## What that means for a client

- A single change to an idle zone is served and answered as before.
- A busy zone serves a change, and answers the UPDATE or API call that made it, up to one cadence later. A client that waits for each answer before sending the next runs at one change per cadence. Concurrent changes share a serial.
- Every answer still means what it meant: NOERROR, or a 200 from the API, says the change is durable and served. Senders wait the larger of 10 seconds and twice the cadence for it.
- The operator's own publish, `zone bump`, is immediate, and its answer says so when a hold stopped it.

## Transactions

A writer can group changes into a transaction (TX-BEGIN, TX-COMMIT on the update queue, or in process). While one is open the zone is **held**: nothing it staged is served until the commit, and a transfer that arrives meanwhile is refused and retried after 5 seconds. A hold ends with the commit, or by its limit (30 seconds per transaction), or by the hold's cap (60 seconds from the first begin) if a writer keeps opening transactions. A released hold on a published zone logs a WARN and publishes what was staged; on a zone that has never published it fails closed, with `FirstPublishError`, until a commit comes. tdns-mp's identity zone is such a transaction at start.

## What to look at

- `tdns-cli <role> debug zone-txlog -z <zone>` shows what is staged and not yet served: the owners a pending publish changes, whether a publish is queued and when it is due, the senders waiting for it, whether the zone is held and since when, and each open transaction with its age and limit.
- `zone list` carries a zone's errors: a hold past its cap on a zone that has never published shows there as `FirstPublishError`. The limit, and the cap on a published zone, are WARN lines in the log.
- Log lines to know: "the refreshed zone was not applied; retrying shortly" (a refresh refused under a hold, or over a change the zone could not publish yet); "a transaction is past the hold's limit"; "the hold is past its age cap"; "publish: refusing to publish unsigned content" (a change staged on a zone that cannot sign yet waits for the pass that can).
