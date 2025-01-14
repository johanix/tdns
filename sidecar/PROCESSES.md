Lorem ipsum

```mermaid
sequenceDiagram
    participant Signer
    participant Leader
    participant Follower
    participant Parent
    Leader->>Follower: zone.parent.follower. NS ?
    Follower-->>Leader: zone.parent.follower. NS RRset
    Note over Leader: Compute new NS RRset = own NS RRset + Follower NS RRset
    alt New NS RRset equal to old NS RRset?
       Note over Leader: No action. Terminate.
    else
       Leader-->>Follower: UPDATE NS RRset
       Follower-->>Leader: NOERROR
       Leader-->>Signer: UPDATE NS RRset
       Signer-->>Leader: NOERROR
       Note over Leader: Compute new CSYNC RRset
       Leader-->>Follower: UPDATE CSYNC RRset
       Follower-->>Leader: NOERROR
       Leader-->>Signer: UPDATE CSYNC RRset
       Signer-->>Leader: NOERROR
       Note over Leader: POLL Parent until NS RRset updated
       Leader-->>Parent: zone.parent. NS ?
       Parent-->>Leader: NOERROR
   end

```

Lorem ipsum
