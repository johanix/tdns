# TDNS-AGENT

**TDNS-AGENT** is a slightly more limited version of **TDNS-SERVER**.
Primarily the limitation is that it is only able to operate as a
secondary, not a primary. The intent is to enable zones that have a
well-working zone production pipeline to easily attach the
*tdns-agent* as an additional secondary and thereby gain access to the
TDNS features without the need to modify the zone production.

Design constraints for the TDNS Agent:

1. Essentially all configuration errors should be fatal. There is no
   point to an agent that is running on a partially broken config.

2. The **tdns-agent** can only serve secondary zones. Any primary zone in the
   configuration should cause the agent to terminate.

3. Can not make modifications to zones. I.e. the options
   online-signing, publish-key, allow-updates and allow-child-updates are errors and
   should cause the agent to terminate.

4. What the agent CAN do is to detect changes to delegation
   information and when that happens take action. Depending on what
   schemes the parent supports the action is either to send a generalized
   NOTIFY or create, sign and send a DNS UPDATE.

5. Not having either of the options delegation-sync-parent and/or
   delegation-sync-child for a zone is an error, as then there is no
   point to the agent being configured to deal with that zone.

```mermaid
graph TD
    subgraph AgentRegistry
        A1[HelloHandler]
        A2[HeartbeatHandler]
        A3[MsgHandler]
        A4[CommandHandler]
        A5[HelloRetrier]
        A6[SendHeartbeats]
        A7[EvaluateHellos]
    end

    subgraph Channels
        C1[HelloQ]
        C2[BeatQ]
        C3[MsgQ]
        C4[CommandQ]
        C5[DebugCommandQ]
        C6[SyncQ]
        C7[SyncStatusQ]
    end

    subgraph APIrouter
        H1[APIagent]
        H2[APIagentDebug]
        H3[APIkeystore]
        H4[APItruststore]
    end

    subgraph APIAgentSyncRouter
        H10[APIhello]
        H11[APIbeat]
        H12[APImsg]
    end

    subgraph HsyncEngine
        E1[HsyncEngine]
    end

    subgraph DNS
        D1[DnsEngine]
        D2[QueryResponder]
        D3[NotifyResponder]
        D4[UpdateResponder]
    end

   subgraph ZoneUpdater
        D5[ZoneUpdater]
   end

   subgraph RefreshEngine
      D6[RefreshEngine]
   end

    subgraph CombinerUpdater
        D10[CombinerUpdater]
    end

    subgraph DelegationSyncher
       D11[DelegationSyncher]
    end

    subgraph Zones
      Z1[ConcurrentMap w/ zone data]
    end

    subgraph KeyStore
      Z2[Database]
    end

    subgraph TrustStore
      Z3[Database]
    end

    subgraph Config
        F1[SetupAgent]
        F2[SetupApiTransport]
        F3[SetupDnsTransport]
        F4[ParseConfig]
        F5[ParseZones]
    end

   D1 -->|sends to| D2
   D1 -->|sends to| D3
   D1 -->|sends to| D4
   D4 -->|sends to| D5
   D1 -->|uses| Z1
   D2 -->|uses| Z1
   D5 -->|uses| Z1
   D6 -->|uses| Z1
   F5 -->|sends to| D6
   D3 -->|sends to| D6

    E1 -->|calls| A1
    E1 -->|calls| A2
    E1 -->|calls| A3
    E1 -->|calls| A4
    E1 -->|calls| A5
    E1 -->|calls| A6
    E1 -->|calls| A7

    C1 -->|sends to| E1
    C2 -->|sends to| E1
    C3 -->|sends to| E1
    C4 -->|sends to| E1
    C5 -->|sends to| E1
    C6 -->|sends to| E1
    C7 -->|sends to| E1

    H1 -->|sends to| C4
    H2 -->|sends to| C5
    H10 -->|sends to| C1
    H11 -->|sends to| C2
    H12 -->|sends to| C3

    F1 -->|configures| E1
    F2 -->|configures| E1
    F3 -->|configures| E1

    A3 -->|sends to| D10

```