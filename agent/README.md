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

    subgraph APIHandlers
        H1[APIagent]
        H2[APIagentDebug]
        H3[APIbeat]
        H4[APIhello]
        H5[APImsg]
    end

    subgraph HsyncEngine
        E1[HsyncEngine]
    end

    subgraph Config
        F1[SetupAgent]
        F2[SetupApiTransport]
        F3[SetupDnsTransport]
    end

    E1 -->|uses| C1
    E1 -->|uses| C2
    E1 -->|uses| C3
    E1 -->|uses| C4
    E1 -->|uses| C5
    E1 -->|uses| C6
    E1 -->|uses| C7

    C1 -->|sends to| A1
    C2 -->|sends to| A2
    C3 -->|sends to| A3
    C4 -->|sends to| A4
    C5 -->|sends to| A4
    C6 -->|sends to| A4
    C7 -->|sends to| A7

    H1 -->|interacts with| A4
    H2 -->|interacts with| A4
    H3 -->|interacts with| A2
    H4 -->|interacts with| A1
    H5 -->|interacts with| A3

    F1 -->|configures| E1
    F2 -->|configures| E1
    F3 -->|configures| E1
```