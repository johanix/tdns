# **tdns-combiner**

Description

**tdns-combiner** is a small, single-purpose service that controls the four
apex RRsets — NS, DNSKEY, CDS and CSYNC for zones that it receives via
inbound zone transfer (typically from a zone owner) and (after possible
modifications) publishes via outbound zone transfer (to a signer).

The replacement data for the four RRsets is received via an API
connection from a nearby **tdns-agent**.

## Design Constraints for **tdns-combiner**

1. Essentially all configuration errors should be fatal. There is no
   point to a **tdns-combiner** that is running on a partially broken config.

2. The semantics of replacement of data is as follows:

   2.1. DNSKEY, CDS and CSYNC: if there is replacement data, then use
        that.  Otherwise remove any CDS or CSYNC RRs from the inbound,
        unsigned zone.

   2.2. NS: if there is replacement data, then use that. Otherwise
        leave the original NS RRset from the inbound, unsigned, zone
        intact.






