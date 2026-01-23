# tdns-imr

A simple DNS IMR (Iterative Mode Resolver, i.e. a recursive DNS nameserver).

Features:

- **tdns-imr** does recursive lookups, caches intermediate referrals and final
  response (if any)

- incoming queries are first matched against the cache before initiating
  lookup via external queries

- if **tdns-imr** is started without arguments (the normal case) it will enter
  a command loop (i.e. it provides an interactive CLI). 

- supports modern DNS transports (DoT, DoH and DoQ) in addtion to Do53 (UDP/TCP).

Planned, not yet implemented:

- Understand and cache ALPN signaling from authoritative nameservers via the
  opportunistic inclusion of an SVCB record in the Additional section on
  responses.

- Use authoritiative nameserver preferred transport (if any, from the cached
  ALPN data).

The **tdns-imr** interactive CLI has the following implemented or planned
features:

- *query* qname qtype: issue a manual DNS query directly, without going via 
  an external tool like "dig" (or "dog").

- *dump*: Dump the current contents of the recursive cache.

- *dump-only-suffix* *suffix*: Dump the part of the cache with owner names
  ending in the suffix.

- *flush*: Not yet implemented.
