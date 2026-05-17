# tdns-imr

A simple DNS IMR (Iterative Mode Resolver, i.e. a recursive DNS nameserver).

Features:

- **tdns-imr** does recursive lookups, caches intermediate referrals and final
  response (if any)

- incoming queries are first matched against the cache before initiating
  lookup via external queries

- if **tdns-imr** is started without arguments (the normal case) it will enter
  a command loop (i.e. it provides an interactive CLI). 

- supports modern DNS transports (DoT, DoH and DoQ) in addition to Do53 (UDP/TCP).

- consumes transport signals from authoritative nameservers — when an
  SVCB record at `_dns.<ns>` arrives in the Additional section (or via
  active discovery, see `query-for-transport` /
  `always-query-for-transport`), tdns-imr parses SvcParam key 65280,
  updates the server's transport preferences in the referral cache, and
  promotes the connection mode to "opportunistic" so subsequent queries
  attempt the preferred encrypted transport. TSYNC is supported as an
  alternative carrier. See section 2 of
  [TDNS Special Features](special-features.md) for the full picture.

The **tdns-imr** interactive CLI has the following implemented or planned
features:

- *query* qname qtype: issue a manual DNS query directly, without going via 
  an external tool like "dig" (or "dog").

- *dump*: Dump the current contents of the recursive cache.

- *dump-only-suffix* *suffix*: Dump the part of the cache with owner names
  ending in the suffix.

- *flush*: Not yet implemented.
