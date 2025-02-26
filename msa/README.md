# MUSIC-SIDECAR

**MUSIC-SIDECAR** is a version of **MUSICD** that is intended for
distributed operation. The idea is to have one "sidecar" next to each
DNSSEC signer.

The **MUSIC-SIDECAR** must be configured as a secondary from the
signers POV, i.e. NOTIFIES must be sent and zone transfer requests
from the sidecar responded to.

The intent is to enable zones that have a well-working zone production
pipeline, including signers, to easily attach the *music-sidecar* as
an additional secondary and thereby gain access to the MUSIC
multi-signer features without the need to modify the zone production.

Technically **MUSIC-SIDECAR** is implemented as a modified **MUSICD**
that is linked against the TDNS library. The library provides an
implementation of all the DNS-server pieces.

Implementation status:

Just started. While the functionality inherited from TDNS exists, none
of the multi-signer features are integrated yet (i.e. the code is
there, but not integrated, it only compiles).

Usage model:

1. When a new zone is added to the signer via a zone transfer from a zone
   owner then that zone should contain one or more MSIGNER records.

2. When the zone is signed by the signer, the sidecar is notified and
   transfers the zone. The sidecar then looks for the MSIGNER RRset,
   which lists the identity of the sidecars (as representatives for the
   signers) for the zone. The sidecar should now contact each of the
   other signers, establish a secure communication channel with each
   signer and initiate a heartbeat among the signers.

3.  

Design constraints for the MUSIC-SIDECAR:

1. Essentially all configuration errors should be fatal. There is no
   point to an agent that is running on a partially broken config.

2. The **music-sidecar** can only act as a secondary for zones. Any primary zone in the
   configuration should cause the sidecar to terminate.

3. MUSIC-SIDECAR can not make modifications to zones. I.e. the TDNS options
   online-signing, publish-key, allow-updates and allow-child-updates are
   errors and should cause the sidecar to terminate.

4. What the sidecar CAN do is to detect changes to delegation
   information, DNSKEYs, etc and when that happens take action. Typical
   action is to notify the other sidecars (sitting next to each of the
   other signers) about the event and initiate a "multi-signer process" to
   get everything back in sync again.

5. When a multi-signer process is initiated it starts with an election
   of a "leader" for the process. The leader is responsible for tracking
   and directing the collective progress through the multi-signer process.

