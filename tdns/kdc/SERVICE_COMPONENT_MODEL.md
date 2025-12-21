# Service-Component Model for Zone-to-Node Relationships

## Overview

This document describes the service-component model for managing which zones are served by which nodes. This model enables precise "blast zone" calculation when a node is compromised.

## Model Architecture

### Entities

1. **Service**: A logical grouping of zones (e.g., "customer-service", "internal-service")
2. **Component**: A part of a service that can serve zones (e.g., "web-component", "api-component")
3. **Zone**: A DNS zone (already existed, now enhanced with `service_id` and `signing_mode`)
4. **Node**: An edge server that receives ZSK keys (already existed)

### Relationships

```
Zone → Service (many-to-one)
  Each zone belongs to one service (optional for backward compatibility)

Service → Component (many-to-many)
  A service can have multiple components
  A component can belong to multiple services

Component → Zone (many-to-many)
  A component can serve multiple zones
  A zone can be served by multiple components

Node → Component (many-to-many)
  A node can serve multiple components
  A component can be served by multiple nodes
```

### Zone Signing Modes

Each zone has a `signing_mode` that determines how it's signed:

- **`upstream`**: Already signed by upstream, we just serve it (no key distribution)
- **`central`**: Centrally signed, no private keys distributed to nodes (default)
- **`edgesign_dyn`**: ZSK distributed, signs dynamic responses only (negative responses, synthesized data). Central signer still signs positive, static responses.
- **`edgesign_zsk`**: ZSK distributed, signs all responses. Distributed zone is unsigned except for DNSKEY RRset (signed by non-distributed KSK).
- **`edgesign_all`**: KSK+ZSK distributed, all signing at edge. Required for network partitioning scenarios.
- **`unsigned`**: No DNSSEC signing

**Key Distribution Rules:**
- Only zones with `edgesign_dyn`, `edgesign_zsk`, or `edgesign_all` modes receive private keys.
- Zones with `edgesign_all` require both KSK and ZSK distribution.
- Zones with `edgesign_dyn` or `edgesign_zsk` require only ZSK distribution.

## Blast Zone Calculation

When a node is compromised, the blast zone is calculated as follows:

1. **Find components served by the compromised node**
   - Query `node_component_assignments` where `node_id = <compromised_node>` and `active = 1`

2. **Find zones served by those components**
   - For each component, query `component_zone_assignments` where `component_id = <component>` and `active = 1`

3. **Filter to edgesign_* zones**
   - Zones with `signing_mode IN ('edgesign_dyn', 'edgesign_zsk', 'edgesign_all')` require immediate ZSK rollover
   - Zones with `signing_mode = 'edgesign_all'` also require KSK rollover
   - Zones with other signing modes are not affected (no keys distributed)

4. **Result**: List of zones that need immediate ZSK rollover

### Example

```
Node "edge-01" is compromised
  → Serves components: ["web-component", "api-component"]
  → Components serve zones: 
       web-component: ["example.com", "test.com"]
       api-component: ["api.example.com", "internal.example.com"]
  → Filter by signing_mode IN ('edgesign_dyn', 'edgesign_zsk', 'edgesign_all'):
       example.com (edgesign_zsk) ✓ needs ZSK rollover
       test.com (central) ✗ no rollover needed
       api.example.com (edgesign_dyn) ✓ needs ZSK rollover
       internal.example.com (upstream) ✗ no rollover needed
       secure.example.com (edgesign_all) ✓ needs ZSK+KSK rollover
  → Blast zone: ["example.com", "api.example.com", "secure.example.com"]
```

## Database Schema

### New Tables

- `services`: Service definitions
- `components`: Component definitions
- `service_component_assignments`: Many-to-many relationship between services and components
- `component_zone_assignments`: Many-to-many relationship between components and zones
- `node_component_assignments`: Many-to-many relationship between nodes and components

### Updated Tables

- `zones`: Added `service_id` (nullable) and `signing_mode` (default: 'central')

## API Functions

### Blast Zone Calculation

```go
// Calculate blast zone for a compromised node
result, err := kdcDB.CalculateBlastZone(nodeID)
// Returns: BlastZoneResult with affected zones and edgesigned zones
```

### Node Selection for Distribution

```go
// Get nodes that serve a zone (via components)
nodes, err := kdcDB.GetActiveNodesForZone(zoneName)
// Returns: []*Node - only nodes that serve this zone through components
```

### Component Operations

- `GetComponentsForNode(nodeID)`: Get all components served by a node
- `GetZonesForComponent(componentID)`: Get all zones served by a component
- `GetNodesForComponent(componentID)`: Get all nodes that serve a component

## Distribution Logic

When distributing keys:

1. **Check zone signing mode**
   - If `signing_mode NOT IN ('edgesign_dyn', 'edgesign_zsk', 'edgesign_all')`, reject distribution (keys not distributed to nodes)
   - Only `edgesign_*` zones can have keys distributed
   - For `edgesign_all` zones, both KSK and ZSK can be distributed
   - For `edgesign_dyn` and `edgesign_zsk` zones, only ZSK is distributed

2. **Get nodes for zone**
   - Use `GetActiveNodesForZone(zoneName)` instead of `GetActiveNodes()`
   - This returns only nodes that serve the zone through components

3. **Encrypt and distribute**
   - Encrypt key for each node that serves the zone
   - Create distribution records

## Migration Notes

- Existing zones will have `service_id = NULL` and `signing_mode = 'central'` (default)
- The old `zone_node_assignments` table is kept for backward compatibility but deprecated
- New zones should be assigned to services and components
- Zones can be migrated gradually to the new model
- When migrating zones to edgesign modes, ensure proper component assignments are in place

## Benefits

1. **Precise blast zone calculation**: Only edgesigned zones in affected components need rollover
2. **Flexible zone assignment**: Zones can be served by multiple components, components by multiple nodes
3. **Clear signing semantics**: Explicit signing modes make it clear which zones need key distribution
4. **Scalable**: Supports complex service architectures with multiple components and nodes

