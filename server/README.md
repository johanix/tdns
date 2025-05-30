# TDNS-SERVER

**TDNS-SERVER** is small authoritative DNS name server with support for a baseline
feature set:

0. Load zones from text files on disk.

1. Inbound and outbound NOTIFY support. Inbound and outbound
   AXFR support. No support for IXFR yet.

2. Respond correctly to non-DNSSEC queries.

3. Respond mostly correctly to queries with DO=1 to DNSSEC signed
   zones. The support for negative responses is not quite complete.

4. TDNS-SERVER is able to sign (including generating the NSEC chain) a zone 
   via a command from "**tdns-cli**". It is also able to perform online 
   signing of unsigned zones that are configured to allow that (if
   TDNS-SERVER has access to suitable keys to sign with).

The TDNS-SERVER configuration is in the file tdns-server.yaml, by default
located in **/etc/tdns/tdns-server.yaml**

In addition, TDNS-SERVER has a couple of extra features:

1. There is a built in REST API, used by the mgmt tool "tdns-cli".

2. Support for inbound, SIG(0) signed, dynamic updates.
   No TSIG support (yet).

3. Support for publication of the DSYNC RRtype (see 
   draft-ietf-dnsop-generalized-notify).

4. Support for detecting changes to an authoritative zone's delegation
   data on reload from file, inbound zone transfer or received DNS
   UPDATE.  If delegation data has changed, the server (as an agent for
   the child) is able to attempt synchronization of the delegation by
   interacting with the parent via generalized NOTIFY or SIG(0) signed
   UPDATE messages.

5. Support for receiving generalised notifications (as an agent for
   the parent). Note that at present TDNS-SERVER doesn't do much with the
   received notifications, as it does not have a built in CDS and/or
   CSYNC scanner. In the future there may be a separate scanner that
   TDNS-SERVER will interact with.

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
   and receiving then via zone transfer.

10. Support for a built in keystore (to store private/public DNSSEC
    and SIG(0) key pairs). These are used to sign zone data and DNS
    UPDATE messages.

11. Support for a built in truststore (to store public DNSSEC and 
    SIG(0) keys). These are used to validate child CDS and CSYNC
    RRsets and DNS UPDATE messages received from child operstors.

Comments, questions, pull requests, etc are welcome!

Johan Stenstam
