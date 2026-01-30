# Agent–Combiner Secure Comms (No Enrollment)

Single-org setup: no explicit enrollment. Generate JOSE keypairs, configure each side with the other’s address and public key.

## Storage: Where to put the keypair

**Recommendation: file paths in YAML config (no DB for keys).**

- **Private key**: path in config (e.g. `long_term_jose_priv_key: /etc/tdns/agent.jose.private`). Key material stays in a file with strict permissions, not in YAML or DB.
- **Public key**: path in config for the *other* party (e.g. `long_term_jose_pub_key: /etc/tdns/combiner.jose.pub`). Our own public key can be derived from the private key when needed (e.g. for “show” or for writing a `.pub` file next to the priv key).
- **Why not DB**: DB is good for dynamic/relational data (agents, zones). Keys are static and small; files give clearer lifecycle (generate once, chmod 600, backup). Matches KDC/KRS pattern (`kdc_jose_priv_key` in config).
- **Why not inline in YAML**: Inline private key in YAML is a bad idea (backups, logging, world-readable configs). Path reference is safer.

## What we have

- **JOSE backend** (`tdns/v2/crypto/jose`): `GenerateKeypair()`, `SerializePublicKey` / `SerializePrivateKey`, `ParsePublicKey` / `ParsePrivateKey` (JWK JSON). Ready for generate + load from file.
- **Transport crypto** (`tdns/v2/agent/transport/crypto.go`): `PayloadCrypto`, `SetLocalKeys`, `AddPeerKey` / `AddPeerVerificationKey` for CHUNK JWS/JWE. Not yet fed from config.
- **Config**: `LocalAgentConf` (agent identity, API/DNS, Xfr). No `combiner` peer or JOSE key path. Combiner uses same `Config`; no `agent` peer or JOSE key path.
- **CLI**: `tdns-cli` (cliv2) talks to API; no “keys generate” / “keys show”. Agent and combiner binaries are daemon-only (no subcommands).

## What needs to be implemented

1. **Config** (implemented)
   - **Agent**: Under `agent`: `long_term_jose_priv_key` (path), and `combiner: { address, long_term_jose_pub_key }` (path).
   - **Combiner**: Top-level `agent_peer: { address, long_term_jose_pub_key }` and `long_term_jose_priv_key` (path). (We use `agent_peer` to avoid YAML key conflict with the shared `agent` section used for agent identity.)

2. **CLI** (implemented)
   - Keys are under **tdns-cli**, not the server binaries. Agent and combiner are daemons only (no subcommands).
   - **Agent**: `tdns-cli agent keys generate [-o path]`, `tdns-cli agent keys show`. Uses the agent's config file (set `config_file` for the tdns-agent entry in tdns-cli's apiservers, or pass `--server-config`).
   - **Combiner**: `tdns-cli combiner keys generate [-o path]`, `tdns-cli combiner keys show`. Same idea with combiner config file.

3. **Runtime**
   - Load our key from `long_term_jose_priv_key` and peer key(s) from `long_term_jose_pub_key` at startup; pass to `PayloadCrypto` / `SecurePayloadWrapper` so CHUNK traffic (e.g. ping, sync) can use JWS/JWE when configured.
