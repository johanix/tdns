# AGENT-to-AGENT (or provider-to-provider) Synchronization Processes

There are a number of different synchronization tasks between
providers. In some cases, the zone owner will also be involved,
depending on the zone owners intent regarding delegation (or
designation) of various responsibilities.

The following list is intended to be as complete as possible, but
isn't necessarily complete yet.

## Assumptions

A framework for secure communication between all DNS providers (and,
if wanted, also the zone owner) exists. On top if this communication
layer, there is a messaging layer where different types of messages may
be defined and exchanged. All communication consists of a pair of
messages: the outgoing message from one provider to another and the
response back to the originator of the initial message. Both messsages
are authenticated and trusted.

Each provider operates under its own policy which determines what
changes to the customer's (i.e the zone owner's) zone are acceptable.
Responses must include information that make it clear whether the
contents of a message were accepted or rejected according to the local
policy of the recipient.

## Establishing Secure Communication Between Agents

Agents identify each other via the HSYNC RRset. If a zone has no HSYNC
RRset or if the local agent is not present in the HSYNC RRset then no
agent-to-agent communication is needed. If, however, the local agent
is present in the HSYNC RRset, then it needs to identify and locate
all other providers for the zone via their identities as published in
the individual HSYNC RRs. Such remote agents are put in the state
"NEEDED".

For each remote agent (remote provider) communication is established
by looking up the URI for the identity of the remote agent, then the
SVCB for the target of the URI and finally the KEY and/or TLSA for the
target of the URI. All of these lookups MUST be successfully DNSSEC
validated. Once all this information has been collected the remote
agent is moved to the state "KNOWN".

Once KNOWN, the local agent initiates communication by sending a HELLO
message. On receipt of a positive response to the HELLO (from the
remote agent), the remote agent is moved to the state "INTRODUCED".
HELLO messages do not require mTLS. I.e. the recipient will accept
them even if not able to verify the sender.

Once introduced, communication switches to mTLS, i.e. all messages are
signed by the sender and will be discarded by the recipient if they do
not validate. The local agent now starts sending heartbeat messages
according to a local configuration for how often. The heartbeat also
includes the intended frequency, so that the remote agent knows what to
expect. On receipt of a positive response to an HELLO, the remote agent
is moved to the state "OPERATIONAL".

Should, at some late time, multiple outgoing heartbeats not get
positive responses OR the remote agent fail to send incoming
heartbeats (to us) according to its published schedule, the remote
agent is first moved to the state "DEGRADED" (when the delay > 2 x
normal interval) and then to "INTERRUPTED" (when the delay > 10 x
normal interval).

When a remote agent is DEGRADED or INTERRUPTED the local agent
continues to send heartbeats according to schedule. On receipt of a
positive response to such a heartbeat, the remote agent is again
moved back to "OPERATIONAL".

## Defined Message Types

   1. NOTIFY: This is a message from the sender to inform the
      recipient that something has changed that the recipient must be aware
      of and possible cause the recipient to change some local data.

   2. RFI [Request For Information]: This is a message where the
      sender is asking for specific information from the recipient. The
      message must include a reason for the request. One example is for a
      downstream provider to request information from the upstream provider
      about from what IP addresses to request a zone transfer. A similar
      request is from the upstream provider to the downstream provider
      requesting information about from which IP addresses to expect zone
      transfer requests.

   3. ELECTION-START, ELECTION-VOTE, ELECTION-RESULT, ELECTION-INVALID: 

      3.1. ELECTION-START may be triggered by any participant by
           sending an ELECTION-START message to all the other participants. The
           START message must include an election identifier (presumably an
           uuid).

      3.2. ELECTION-VOTE: All participants should respond by sending
           ELECTION-VOTE messages containing the election identifier and a "vote"
           (an uint16) containing a random number) to all others. When a
           participant has received ELECTION-VOTE messages from all others it
           knows who "the winner" is (the participant with the highest vote). If
           a participant receives the exact same "vote" (the same random uint16
           number) from more than one other participant, then it must send an
           ELECTION-INVALID message to all others.

      3.3. ELECTION-RESULT: Each participant MUST send EITHER an
           ELECTION-RESULT message to all others containing the election
           identifier and the identity of the winner of the election OR an
           ELECTION-INVALID message (in the case of conflicting votes).

      3.4. ELECTION-INVALID: Should the incoming ELECTION-RESULT
           contain a different winner than the local provider thinks won, the
           local provider MUST send an ELECTION-INVALID message. On receipt of an
           ELECTION-INVALID message, the originating participant (the sender of
           the ELECTION-START message) may or may not choose to initiate a new
           election, by sending a new ELECTION-START message.

## Synchronizing the contents of the NS RRset

There are multiple providers for a zone. Each provider operates
authoritative nameservers that serve the zone. The NS RRset both in
the zone and in the parent needs to be updated to list the correct set
of NS records to reflect the current setup.

### Messages

If the current NS RRset does not correctly reflect the NS records
provided by the local provider then it (the local provider) MUST send
a NOTIFY message to all others containing a set of "ADD [record]" and
"REMOVE [record]" instructions. These instructions are only for
information to other downstream providers, but need to be acted upon
by either the "primary provider" (for an unsigned zone) or all
"signing providers" (for a signed zone). If a provider that must act
on the instructions decide to reject the update (due to local policy),
it must send back a response clearly stating both the rejection and a
reason for the rejection.

## NS RRset Synchronization Process

When an agent receives internal information (i.e. information from
inside its own provider) that the local contributions to the NS RRset
for the zone are changing it will immediately send a NOTIFY message to
all other agents informing them about this.

The NOTIFY contains the complete set of local contributions, and are
intended to fully replace the previous data for this provider stored
at the remote providers.

It is important to maintain correct DNS semantics for nameservers
included in the NS RRset. I.e. a new nameserver should not be
announced to other providers until it is already fully operational.
Likewise, a nameserver that is being removed should first be removed
from the local contributions to the NS RRset and first when that
change has propagated should the outgoing nameserver stop serving the
zone.

Ensuring correct semantics is the responsibility of the provider
contributing the information.

## Synchronizing the contents of the DNSKEY RRset

NYI.

## Adding a new DNS provider that provides authoritative DNS service 

A new (incoming) DNS provider is signaled by its inclusion in the
HSYNC RRset. As such, all existing providers will automatically notice
the arrival of a new provider.

## Removing a DNS provider that provides authoritative DNS service 

## Exchanging information needed for zone transfer configuration

A downstream provider needs information from its upstream provider
about what IP addresses to request zone transfers from. Likewise, the
upstream needs the corresponding information from the downstream about
what IP address to whitelist for outgoing zone transfers. Either party
may initiate the communication.

### Messages

An initiating party sends an RFI message containing its own
information (for the perusal of the recipient) requesting the
information needed from the recipient. The recipient MUST respond with
either a positive response containing the sought after information OR
a rejection message that clearly states the reason for the rejection.

### Scope Limitation

At this time only IP addresses are included in the information
exchange. XFR-over-TLS (RFC9103) is likely a good alternative to be
able to provide confidentiality given that mTLS is already setup, but
this has not yet been tested.

## Adding a new "signer" (a DNS provider that signs the zone) 

## Removing a "signer" (a DNS provider that signs the zone) 

