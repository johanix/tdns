Lorem ipsum

```mermaid
sequenceDiagram
    participant Leader
    participant Follower
    participant Parent
    participant Signer
    Leader->>Follower: zone.parent.follower NS ?
    Follower-->>Leader: zone.parent.follower. NS RRset
    Leader-->>Leader: Does NS RRset differ?; yes
    Leader-->>Follower: UPDATE NS RRset
    Leader-->>Signer: UPDATE NS RRset
    Follower-->>Leader: NOERROR
    Signer-->>Leader: NOERROR
```

Lorem ipsum
