# TDNS-AUTH

**TDNS-AUTH** is small authoritative DNS name server with support for a baseline
feature set:

0. Load zones from text files on disk.

1. Inbound and outbound NOTIFY support. Inbound and outbound
   AXFR support, optionally TSIG-authenticated. No support for
   IXFR yet. A secondary zone may be configured with multiple
   primaries, and inbound NOTIFY and outbound AXFR are governed
   by NSD-style access-control lists (see feature 16 below).

2. Respond correctly to non-DNSSEC queries.

3. Respond mostly correctly to queries with DO=1 to DNSSEC-signed
   zones. The support for negative responses is not quite complete.

4. TDNS-AUTH is able to sign (including generating the NSEC chain) a zone 
   via a command from "**tdns-cli**". It is also able to perform online 
   signing of unsigned zones that are configured to allow that (if
   TDNS-AUTH has access to suitable keys to sign with).

The TDNS-AUTH configuration is in the file tdns-auth.yaml, by default
located in **/etc/tdns/tdns-auth.yaml**

In addition, TDNS-AUTH has a couple of extra features:

1. There is a built-in REST API, used by the mgmt tool "tdns-cli".

2. Support for inbound, SIG(0) signed, dynamic updates.

3. Support for publication of the DSYNC RRtype (see 
   draft-ietf-dnsop-generalized-notify).

4. Support for detecting changes to an authoritative zone's delegation
   data on reload from file, inbound zone transfer or received DNS
   UPDATE.  If delegation data has changed, the server (as an agent for
   the child) is able to attempt synchronization of the delegation by
   interacting with the parent via generalized NOTIFY or SIG(0) signed
   UPDATE messages.

5. Support for receiving generalised notifications (as an agent for
   the parent). Note that at present TDNS-AUTH doesn't do much with the
   received notifications, as it does not have a built in CDS and/or
   CSYNC scanner. In the future there may be a separate scanner that
   TDNS-AUTH will interact with.

6. Support for sending generalized notifications (as an agent
   for the child) to the parent's designated NOTIFY Receiver (as 
   documented via publication of one or more DSYNC RRs in the
   parent zone).

7. Support for receiving SIG(0) signed UPDATE messages containing 
   new delegation information for a child zone (as an agent for
   the parent). Acceptance of this data requires the signature to
   validate and is also subject to local policy.

8. Support for sending SIG(0) signed UPDATE messages (as an agent
   for the child) to the parent's designated UPDATE Receiver (as 
   documented via one or more DSYNC RRs in the parent zone).

9. Initial support for the experimental DELEG record type, including
   reading and parsing zones containing DELEG records for text files
   and receiving them via zone transfer.

10. Support for a built-in keystore (to store private/public DNSSEC
    and SIG(0) key pairs, plus shared-secret TSIG keys). These are
    used to sign zone data and DNS UPDATE messages, and to
    authenticate zone transfers and NOTIFY.

11. Support for a built-in truststore (to store public DNSSEC and 
    SIG(0) keys). These are used to validate child CDS and CSYNC
    RRsets and DNS UPDATE messages received from child operators.

12. Full support for DNS Catalog Zones (RFC 9432), including:
    - Primary and secondary catalog zones
    - Configurable group prefixes for flexible categorization
    - Automatic zone discovery and configuration from catalog zones
    - Per-catalog-zone auto-create and auto-delete policies
    - API and CLI support for managing catalog zone membership
    - Notify address management for catalog zones
    - Persistence of catalog zones and their member zones

13. Dynamic zone management via REST API:
    - Create, modify, and delete zones at runtime
    - Support for both primary and secondary dynamic zones
    - Automatic persistence of dynamic zones to disk
    - Dynamic configuration file generation for zone definitions
    - Include statement support for modular configuration

14. Zone templates system:
    - Define reusable zone configuration templates
    - Template inheritance and chaining
    - Reduce configuration duplication for similar zones
    - Override template settings per zone

15. Zone persistence and recovery:
    - Automatic zone file writing for dynamic zones
    - Configuration file persistence for zone definitions
    - Graceful handling of corrupted files on startup
    - Atomic file writes to prevent data loss

16. NSD-style access control for zone transfers and NOTIFY.
    `allow-notify:` (who may NOTIFY a secondary) and
    `downstreams:` (who may AXFR from a primary) are lists of
    entries, each an address prefix plus an optional TSIG key
    name (or the `NOKEY` / `BLOCKED` sentinels). An empty
    `downstreams:` denies all outbound transfers -- a deliberate
    change from the historical open-AXFR default -- so a primary
    must explicitly list the peers it will answer.

17. First-class TSIG (RFC 8945). TSIG keys live in the
    DB-backed keystore (managed via `tdns-cli` and the REST API)
    and are referenced by name from peer (`primaries:`,
    `notify:`) and ACL (`allow-notify:`, `downstreams:`) config.
    A primary specified by hostname rather than IP is resolved
    via the built-in resolver and re-resolved on the refresh
    cadence.

18. DNSSEC signing policies, referenced per zone by name
    (`dnssecpolicy:`), with reusable policy templates: a policy
    may inherit from a named template (`dnssec.templates:`) via
    a `template:` reference, and a deep merge fills in the
    fields the policy does not set itself. See the annotated
    sample config and the key-rollover guide.

## TSIG on queries: optional, but strict once used

How TDNS-AUTH treats TSIG (feature 17) on an ordinary query is a deliberate
**policy** choice, not an RFC-correctness issue — RFC 8945 does not mandate a
particular behaviour on the QUERY opcode:

- An **unsigned** query is answered normally. TSIG is never *required* to query.
- A **correctly signed** query is answered, and the response is itself
  TSIG-signed, so the requester can authenticate the answer.
- A **wrongly signed** query — bad MAC, unknown key, or a timestamp outside the
  fudge window — is **rejected** with `NOTAUTH`, an error TSIG carrying
  `BADSIG` / `BADKEY` / `BADTIME`, and an EDNS Extended DNS Error (EDE) stating
  the reason.

The asymmetry — an *unsigned* query is accepted but a *wrongly signed* one is
refused — is intentional. The only parties that hold a TSIG key are secondaries
and other provisioned partners, and they hold it precisely because they need
authenticated exchanges. A failed signature from such a peer is a real
misconfiguration on their side — a wrong secret, a key left stale after a
rotation, or clock skew — so TDNS-AUTH fails **loud**: the `NOTAUTH` + error-TSIG
+ EDE tells them exactly what is wrong immediately, instead of masking it behind
a silently unauthenticated answer. An ordinary client, which has no key, simply
queries unsigned and is unaffected.

Zone transfers (AXFR/IXFR), dynamic UPDATE, and NOTIFY are stricter still, and
there it is *not* a policy choice: TSIG can be **required** by the
`allow-notify:` / `downstreams:` ACL, so a missing key is refused (`REFUSED`) and
a bad signature is rejected (`NOTAUTH` + error TSIG). TSIG there gates access or
mutation, not merely response authentication.

Comments, questions, pull requests, etc are welcome!

Johan Stenstam
