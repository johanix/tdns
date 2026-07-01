# DOG

**DOG** is a trivial implementation of a DNS query tool, similar to the
much more capable utility "*dig*" (from the BIND distribution). DOG has
support for the new record types (i.e. DSYNC and DELEG) that TDNS-SERVER
implements.

The CLI in to **DOG** is as close to identical to *dig* as possible.

On an error response, **DOG** reports the DNS rcode by name
(REFUSED, SERVFAIL, NOTAUTH, ...) rather than a bare numeric code --
for example, a transfer refused by a `downstreams:` ACL prints
"server returned REFUSED" instead of "rcode 5".
