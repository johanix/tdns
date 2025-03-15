# TDNS-COMBINER

Description

TDNS-COMBINER is intended to be as small and simple as possible and
only serve one single purpose: to control the four apex RRsets for
DNSKEY, CDS, CSYNC and NS for zones that it receives via inbound zone
transfer (from a zone owner) and (after possible modifications)
publishes via outbound zone transfer (to a signer).

The replacement data for the four RRsets is received via an API
connection to a nearby MSA.

Design constraints for TDNS-COMBINER:

1. Essentially all configuration errors should be fatal. There is no
   point to a COMBINER that is running on a partially broken config.

2. The semantics of replacement of data is as follows:

   2.1. DNSKEY, CDS and CSYNC: if there is replacement data, then use
        that.  Otherwise remove any CDS or CSYNC RRs from the inbound,
        unsigned zone.

   2.2. NS: if there is replacement data, then use that. Otherwise
        leave the original NS RRset from the inbound, unsigned, zone
        intact.


