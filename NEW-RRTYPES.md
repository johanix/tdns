**TDNS** supports various experimental DNS RR types:

## DSYNC

An implementation of the DSYNC records as defined in
draft-ietf-dnsop-generalized-notify-NN

## HSYNC

Intended for zone owner signaling of intent towards DNS service providers.
Format:

owner.name.  IN HSYNC {state} {nsmgmt} {sign} {identity} {upstream}

state:       either ON or OFF
nsmgmt:      either OWNER or AGENT
sign:        either SIGN or NOSIGN
identity:    a domain name identifying a DNS provider agent
upstream:    a domain name identifying a DNS provider agent

## DELEG

A start of an implementation of the DELEG record as discussed in the dd@ietf.org WG.

## HSYNC2

Intended for zone owner signaling of intent towards DNS service providers.
Alternative syntax to HSYNC. Format:

owner.name.  IN HSYNC2 {state} "nsmgmt={val}; sign={val}; audit={val}; parentsync={val}" {identity} {upstream}

state:       either ON or OFF
nsmgmt:      either OWNER or AGENT
sign:        either SIGN or NOSIGN
audit:       either YES or NO
parentsync:  one of the four values: OWNER | NOTIFY | UPDATE | API
identity:    a domain name identifying a DNS provider agent
upstream:    a domain name identifying a DNS provider agent

The k/v pairs in the string are not case-sensitive and will be
presented in lower case. They may come in any order in the string. All
four keys are mandatory; none may be skipped and there are no defaults
(to enforce the instruction to be explicit rather than assumed).

## OBE: NOTIFY and MSIGNER

Older RR types replaced by improved versions. NOTIFY was obsoleted by
DSYNC, MSIGNER by HSYNC.
