# Agent Peer Configuration (Static YAML)

This document describes the static YAML configuration for agent-to-agent encrypted communication.

## Quick Start

Add peer agents to your agent configuration:

```yaml
agent:
  identity: agent1.example.com
  long_term_jose_priv_key: /etc/tdns/agent1.jose.private

  combiner:
    address: combiner.example.com:5301
    long_term_jose_pub_key: /etc/tdns/combiner.jose.public

  # Peer agents for direct agent-to-agent communication
  peers:
    agent2.example.com:
      address: agent2.example.com:5301
      long_term_jose_pub_key: /etc/tdns/agent2.jose.public
```

## Key Generation

```bash
# Generate keypair for each agent
tdns-keygen --backend jose --out /etc/tdns/agent1.jose.private

# Distribute public keys to peer agents
scp /etc/tdns/agent1.jose.public agent2:/etc/tdns/agent1.jose.public
scp agent2:/etc/tdns/agent2.jose.public /etc/tdns/agent2.jose.public
```

## Implementation Details

### Startup Sequence

1. Config validation checks all peer public key files exist
2. `initPayloadCrypto()` loads private key and all peer public keys
3. `registerPeerAgents()` registers peers in TransportManager's PeerRegistry
4. Peers are ready for encrypted communication

### Encryption Flow

**Sending (Agent1 → Agent2)**:
- `SecureWrapper.WrapOutgoing("agent2.example.com", payload)`
- Encrypts with agent2's public key (JWE)
- Signs with agent1's private key (JWS)
- Returns: base64-encoded JWS(JWE(payload))

**Receiving (Agent2 from Agent1)**:
- `SecureWrapper.UnwrapIncoming("agent1.example.com", payload)`
- Verifies signature with agent1's public key
- Decrypts with agent2's private key
- Returns: plaintext JSON

### Files Modified

- `config.go`: Added `Peers map[string]*PeerConf` field
- `config_validate.go`: Added peer key file validation
- `main_initfuncs.go`: Extended crypto initialization, added peer registration
- `tdns-agent.sample.yaml`: Added peer configuration examples

## Configuration Reference

### PeerConf Structure

```go
type PeerConf struct {
    Address            string  // host:port for DNS transport
    LongTermJosePubKey string  // path to peer's public key
    ApiBaseUrl         string  // optional: for API transport
    Identity           string  // optional: peer identity
}
```

### Example: Multi-Agent Setup

```yaml
# agent1.yaml
agent:
  identity: agent1.example.com
  long_term_jose_priv_key: /etc/tdns/agent1.jose.private
  peers:
    agent2.example.com:
      address: 192.0.2.10:5301
      long_term_jose_pub_key: /etc/tdns/agent2.jose.public
    agent3.example.com:
      address: 192.0.2.20:5301
      long_term_jose_pub_key: /etc/tdns/agent3.jose.public
```

## Testing

### Manual Testing (once CLI commands are implemented)

```bash
# From agent1, ping agent2
tdns-cli agent peer ping agent2.example.com
```

### Debug Logging

Enable debug mode to see crypto operations:

```yaml
service:
  debug: true
```

Look for:
- `initPayloadCrypto: Loaded peer X public key from ...`
- `registerPeerAgents: Registered peer X with address ...`

## Troubleshooting

**"no encryption key for peer X"**
- Verify peer is in `agent.peers` section
- Check public key file path and existence

**"failed to decrypt payload"**
- Ensure both agents have each other's current public keys
- Verify keys haven't been regenerated without redistribution

**Config validation errors**
- Check all peer public key file paths
- Ensure files are readable by tdns-agent process

## Next Steps

1. CLI commands for agent-to-agent ping
2. DNS-based key discovery (requires DNSSEC-signed zones)
3. Update LocateAgent() to use internal resolver

## See Also

- `AGENT-to-AGENT.md` - High-level synchronization architecture
- `README.md` - General agent documentation
- RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK)
