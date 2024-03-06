# TDNSD

A small DNS server that does two things:

1. Listen for Notifies for known zones, and upon receiving a Notify
   try to do an inbound AXFR from the configured upstream source.

2. Filter the received zone from any DNSSEC RRs.

3. Provide outbound AXFR service (i.e. respond to SOA and AXFR 
   requests) to downstream servers.
