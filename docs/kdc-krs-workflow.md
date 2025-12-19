# KDC/KRS Workflow Guide

This guide provides step-by-step instructions for setting up and using the HPKE-based DNSSEC key distribution infrastructure with `tdns-kdc` (Key Distribution Center) and `tdns-krs` (Key Receiving Service).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Initial Setup](#initial-setup)
3. [Adding Zones](#adding-zones)
4. [Adding Edge Nodes](#adding-edge-nodes)
5. [Generating DNSSEC Keys](#generating-dnssec-keys)
6. [Key State Management](#key-state-management)
7. [Distributing Keys](#distributing-keys)
8. [Verifying Key Distribution](#verifying-key-distribution)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

Before starting, ensure you have:

- `tdns-kdc` daemon installed and configured
- `tdns-krs` daemon installed and configured (on edge nodes)
- `tdns-cli` command-line tool installed
- HPKE keypairs generated for each edge node
- Network connectivity between KDC and KRS nodes
- DNS infrastructure configured (control zone served by KDC)

## Initial Setup

### 1. Generate HPKE Keypairs for Edge Nodes

For each edge node, generate a long-term HPKE keypair:

```bash
# Generate HPKE keypair for an edge node
tdns-cli debug hpke-generate --prefix /etc/tdns/krs/cpt.axfr.net

# This creates:
# - /etc/tdns/krs/cpt.axfr.net.publickey  (32 bytes, hex-encoded)
# - /etc/tdns/krs/cpt.axfr.net.privatekey (32 bytes, hex-encoded)
```

**Important**: The public key file will be used when adding the node to the KDC. The private key file must be kept secure and is used by the KRS daemon.

### 2. Configure KDC

Edit `/etc/tdns/tdns-kdc.yaml` (see `kdc/tdns-kdc.sample.yaml` for reference):

```yaml
kdc:
   database:
      type: sqlite  # or "mariadb" for production
      dsn: "/var/lib/tdns/kdc.db"
   control_zone: "kdc.example.com."
   default_algorithm: 15  # ED25519
   standby_key_count: 2
   publish_time: 24h
   retire_time: 30d
   jsonchunk_max_size: 60000
```

### 3. Configure KRS (Edge Node)

Edit `/etc/tdns/tdns-krs.yaml` (see `krs/tdns-krs.sample.yaml` for reference):

```yaml
krs:
   database:
      dsn: "/var/lib/tdns/krs.db"
   node:
      id: "cpt.axfr.net."  # FQDN with trailing dot, must match KDC
      long_term_priv_key: "/etc/tdns/krs/cpt.axfr.net.privatekey"
      kdc_address: "192.0.2.1:5354"  # KDC DNS server address
   control_zone: "kdc.example.com."
```

**Critical**: The `node.id` must be a Fully Qualified Domain Name (FQDN) with a trailing dot, and it must match exactly the node ID used when adding the node to the KDC.

### 4. Start the Daemons

```bash
# Start KDC
systemctl start tdns-kdc

# Start KRS (on edge node)
systemctl start tdns-krs
```

## Adding Zones

Add zones to the KDC that will receive DNSSEC key distribution:

```bash
# Add a zone
tdns-cli kdc zone add --zone foffa.se.

# List all zones
tdns-cli kdc zone list

# Get zone details
tdns-cli kdc zone get --zone foffa.se.
```

## Adding Edge Nodes

Register edge nodes with the KDC. Each node must have a unique HPKE public key:

```bash
# Add an edge node
tdns-cli kdc node add \
   --nodeid cpt.axfr.net \
   --nodename "CPT Edge Node" \
   --pubkeyfile /etc/tdns/krs/cpt.axfr.net.publickey

# List all nodes
tdns-cli kdc node list

# Get node details
tdns-cli kdc node get --nodeid cpt.axfr.net
```

**Important Notes**:
- The `--nodeid` should be provided without a trailing dot; the CLI will normalize it to FQDN format
- The public key file must contain the 32-byte X25519 public key (hex or base64 encoded)
- Each node must have a unique public key

### Setting Notify Addresses

For the KDC to send NOTIFY messages to edge nodes, configure the notify address:

```bash
# Update node notify address
tdns-cli kdc node update \
   --nodeid cpt.axfr.net \
   --notify-address 192.0.2.10:5355

# Verify the update
tdns-cli kdc node list
```

The notify address should point to the KRS daemon's DNS engine address (configured in `krs.dnsengine.addresses`).

## Generating DNSSEC Keys

Generate DNSSEC keys for zones. The KDC supports KSK (Key Signing Key), ZSK (Zone Signing Key), and CSK (Combined Signing Key) types:

```bash
# Generate a ZSK for a zone (most common)
tdns-cli kdc zone dnssec generate \
   --zone foffa.se. \
   --type ZSK \
   --algorithm ED25519

# Generate a KSK
tdns-cli kdc zone dnssec generate \
   --zone foffa.se. \
   --type KSK \
   --algorithm ED25519

# List all keys for a zone
tdns-cli kdc zone dnssec list --zone foffa.se.

# List all keys (all zones)
tdns-cli kdc zone dnssec list
```

**Key States**: Newly generated keys start in the `created` state. They must be transitioned through the following states:
- `created` → `published` → `standby` → `active` (or `distributed` → `edgesigner`)
- Keys in `standby` state are ready for distribution to edge nodes

## Key State Management

### Automatic State Transitions

The KDC includes a background worker (`KeyStateWorker`) that automatically transitions keys:

- **`published` → `standby`**: After `publish_time` (default: 24h), keys automatically transition to `standby`
- **`retired` → `removed`**: After `retire_time` (default: 30d), keys are automatically removed
- **`standby` key pool**: The worker ensures there are always `standby_key_count` (default: 2) standby ZSKs available
- **Active KSK**: The worker ensures there is always an active KSK for each zone

### Manual State Transitions

For manual control, use the transition command:

```bash
# Auto-detect and transition (created → published or standby → active)
tdns-cli kdc zone transition --zone foffa.se. --keyid 4664

# Force a key to a specific state (debug command)
tdns-cli kdc zone setstate \
   --zone foffa.se. \
   --keyid 4664 \
   --state standby
```

**Valid States**:
- `created`: Key generated but not yet published
- `published`: Key published in DNSKEY RRset, waiting for cache expiration
- `standby`: Key ready for distribution (automatically maintained pool)
- `active`: Key actively signing zone data
- `distributed`: Key distributed to edge nodes (transitional)
- `edgesigner`: Key received by edge node and ready to use
- `retired`: Key no longer signing, waiting for RRSIG expiration
- `removed`: Key completely removed from system

## Distributing Keys

### Distributing a Standby ZSK

To distribute a ZSK to all active edge nodes:

```bash
# Distribute a standby ZSK
tdns-cli kdc zone distribute-zsk \
   --zone foffa.se. \
   --keyid 4664
```

**What Happens**:
1. KDC encrypts the private key for each active node using HPKE
2. KDC creates a distribution record with a unique `distributionID`
3. KDC sends NOTIFY messages to all active nodes with the `distributionID` in the QNAME
4. Each KRS receives the NOTIFY and queries for `JSONMANIFEST` records
5. KRS fetches `JSONCHUNK` records containing the encrypted keys
6. KRS decrypts the keys and stores them in its database
7. Keys are stored with state `edgesigner` (ready to use)

### Distribution Flow

```
KDC: distribute-zsk command
  ↓
KDC: Encrypt key for each active node
  ↓
KDC: Store distribution records
  ↓
KDC: Send NOTIFY(<distributionID>.<controlzone>) to each node
  ↓
KRS: Receive NOTIFY
  ↓
KRS: Query JSONMANIFEST(<nodeid><distributionID>.<controlzone>)
  ↓
KDC: Return manifest with chunk count and metadata
  ↓
KRS: Query JSONCHUNK(<chunkid>.<nodeid><distributionID>.<controlzone>) for each chunk
  ↓
KRS: Reassemble chunks and decrypt keys
  ↓
KRS: Store keys in database (state: edgesigner)
```

## Verifying Key Distribution

### On KDC Side

```bash
# List all keys for a zone
tdns-cli kdc zone dnssec list --zone foffa.se.

# Get key hash (for verification)
tdns-cli kdc zone dnssec hash \
   --zone foffa.se. \
   --keyid 4664
```

### On KRS Side

```bash
# List all received keys
tdns-cli krs keys list

# Get key details
tdns-cli krs keys get --keyid foffa.se.-4664

# Get key hash (for verification)
tdns-cli krs keys hash \
   --keyid 4664 \
   --zone foffa.se.
```

**Key ID Format**: In KRS, keys are stored with IDs in the format `<zone>-<keyid>` (e.g., `foffa.se.-4664`). When using the hash command, you can either:
- Provide both `--keyid` and `--zone` flags (recommended)
- Provide the full ID as `--keyid` (e.g., `foffa.se.-4664`)

### Comparing Key Hashes

To verify that the key received by KRS matches the key in KDC:

```bash
# Get hash from KDC
KDC_HASH=$(tdns-cli kdc zone dnssec hash --zone foffa.se. --keyid 4664 | grep "Key Hash" | awk '{print $4}')

# Get hash from KRS
KRS_HASH=$(tdns-cli krs keys hash --keyid 4664 --zone foffa.se. | grep "Key Hash" | awk '{print $4}')

# Compare (should be identical)
if [ "$KDC_HASH" == "$KRS_HASH" ]; then
   echo "Keys match!"
else
   echo "Keys do NOT match!"
fi
```

## Troubleshooting

### Node Not Receiving NOTIFYs

1. **Check notify address configuration**:
   ```bash
   tdns-cli kdc node list
   ```
   Ensure the `notify_address` is set and points to the KRS DNS engine address.

2. **Verify KRS is listening**:
   ```bash
   # Check KRS logs
   tail -f /var/log/tdns/tdns-krs.log
   
   # Test NOTIFY manually (from KDC)
   dig @127.0.0.1 -p 5355 +notcp +noall +answer +question \
      <distributionID>.kdc.example.com. NOTIFY
   ```

3. **Check firewall rules**: Ensure UDP/TCP port 5355 (or your configured port) is open.

### Keys Not Appearing in KRS

1. **Check distribution status**:
   ```bash
   # List distributions in KDC
   tdns-cli kdc debug distrib list
   ```

2. **Manually trigger distribution fetch**:
   ```bash
   # On KRS, manually fetch a distribution
   tdns-cli krs debug distrib fetch --id <distributionID>
   ```

3. **Check KRS logs** for decryption errors or network issues.

### Key Hash Mismatch

If key hashes don't match between KDC and KRS:

1. **Verify the key ID is correct** (check both zone and keytag)
2. **Check for multiple keys with same keytag** (shouldn't happen, but verify)
3. **Re-distribute the key** if corruption is suspected

### Database Issues

1. **SQLite database locked**: Ensure only one process is accessing the database
2. **MariaDB connection errors**: Verify DSN format and credentials
3. **Schema migration issues**: Check database logs for migration errors

## Advanced Operations

### Testing Distribution with Small Chunks

For testing the chunking mechanism with smaller chunk sizes:

```bash
# Set chunk size to 1000 bytes (for testing)
tdns-cli kdc debug set-chunk-size --size 1000

# Generate a test distribution
tdns-cli kdc debug distrib generate \
   --id test123 \
   --node-id cpt.axfr.net. \
   --file /path/to/large-file.txt \
   --content-type clear_text

# Fetch from KRS
tdns-cli krs debug distrib fetch --id test123
```

### Debugging HPKE Encryption/Decryption

```bash
# Test HPKE encryption on KDC
tdns-cli kdc debug hpke-encrypt \
   --keyid 4664 \
   --nodeid cpt.axfr.net \
   --output /tmp/encrypted-key.bin

# Test HPKE decryption on KRS (or locally)
tdns-cli kdc debug hpke-decrypt \
   --encrypted-file /tmp/encrypted-key.bin \
   --private-key-file /etc/tdns/krs/cpt.axfr.net.privatekey
```

## Best Practices

1. **Node IDs**: Always use FQDNs with trailing dots for node IDs to ensure consistency
2. **Key Rotation**: Maintain at least 2 standby ZSKs for rapid rollover scenarios
3. **Monitoring**: Monitor key state transitions and distribution success rates
4. **Backup**: Regularly backup KDC and KRS databases
5. **Security**: Keep HPKE private keys secure and restrict file permissions
6. **Network**: Use DoT or DoQ for production deployments instead of plain Do53
7. **Verification**: Always verify key hashes after distribution

## See Also

- `docs/hpke-design.md` - Detailed technical design document
- `kdc/tdns-kdc.sample.yaml` - KDC configuration reference
- `krs/tdns-krs.sample.yaml` - KRS configuration reference

