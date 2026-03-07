# Migration Plan: KDC/KRS to Separate Repository

## Executive Summary

This document outlines the plan to migrate KDC (Key Distribution Center) and KRS (Key Receiving Service) from the TDNS repository into a separate repository (`tdns-kms` or similar). The goal is to keep TDNS focused purely on DNS protocol implementation, while moving all business logic, operational concerns, and key management to a dedicated repository.

## Current State

### What's in TDNS Today

**KDC/KRS Code:**
- `tdns/kdc/` - All KDC business logic
- `tdns/krs/` - All KRS business logic
- `tdns/kdc_init.go` - Integration code (bridges TDNS framework to KDC)
- `tdns/krs_init.go` - Integration code (bridges TDNS framework to KRS)
- `tdns/cli/kdc_cmds.go` - CLI commands for KDC
- `tdns/cli/krs_cmds.go` - CLI commands for KRS

**Shared/Generic Code (stays in TDNS):**
- `tdns/hpke/` - HPKE implementation (generic crypto, stays)
- `tdns/code/` - JSONMANIFEST, JSONCHUNK RRtypes (generic, stays)

### Current Dependency Direction

```
TDNS → imports/aware of KDC/KRS
```

This is problematic because:
- TDNS users who only want DNS protocol must still have KDC/KRS code
- TDNS is no longer purely protocol-focused
- Business logic is mixed with protocol implementation

## Target State

### Desired Dependency Direction

```
tdns-kms → imports TDNS (as library)
TDNS → completely unaware of KDC/KRS
```

### New Repository Structure

```
tdns-kms/
├── cmd/
│   ├── tdns-kdc/
│   │   └── main.go          # Builds tdns-kdc binary
│   └── tdns-krs/
│       └── main.go          # Builds tdns-krs binary
├── kdc/                      # All KDC code (moved from tdns/kdc)
│   ├── structs.go
│   ├── db.go
│   ├── api.go
│   ├── dns_handler.go
│   ├── chunks.go
│   ├── encrypt.go
│   ├── keygen.go
│   ├── key_state_worker.go
│   ├── notify_handler.go
│   ├── blastzone.go
│   └── ...
├── krs/                      # All KRS code (moved from tdns/krs)
│   ├── structs.go
│   ├── db.go
│   ├── api.go
│   ├── jsonchunk.go
│   ├── decrypt.go
│   ├── confirm.go
│   └── ...
├── cli/                      # CLI commands (moved from tdns/cli)
│   ├── kdc_cmds.go
│   └── krs_cmds.go
├── go.mod                    # Imports github.com/johanix/tdns
└── README.md
```

## Required TDNS Changes

### 1. Registration APIs

TDNS needs to expose generic registration APIs that allow external code to plug in handlers without TDNS knowing about the specific use case.

#### DNS Query Handler Registration

```go
// In tdns/tdns/query_handler.go (new or existing)
type QueryHandlerFunc func(ctx context.Context, req *DnsQueryRequest) error

func RegisterQueryHandler(qtype uint16, handler QueryHandlerFunc) error
```

#### DNS NOTIFY Handler Registration

```go
// In tdns/tdns/notify_handler.go (new or existing)
type NotifyHandlerFunc func(ctx context.Context, req *DnsNotifyRequest) error

func RegisterNotifyHandler(handler NotifyHandlerFunc) error
```

#### Engine Registration

```go
// In tdns/tdns/engine.go (new or existing)
type EngineFunc func(ctx context.Context) error

func RegisterEngine(name string, engine EngineFunc) error
```

#### API Route Registration

```go
// In tdns/tdns/api.go (new or existing)
func RegisterAPIRoute(router *mux.Router, path string, handler http.HandlerFunc) error
```

### 2. Configuration Structure

TDNS should support plugin/extensible configuration:

```go
// In tdns/tdns/config.go
type Config struct {
    // ... existing fields ...
    
    // Extensible plugin config
    Plugins map[string]interface{} `yaml:"plugins,omitempty"`
}
```

### 3. Library API

TDNS should expose a clean library API for initialization:

```go
// In tdns/tdns/tdns.go (new)
func New(config *Config) (*Application, error)
func (app *Application) Start(ctx context.Context) error
func (app *Application) GetQueryChannel() chan DnsQueryRequest
func (app *Application) GetNotifyChannel() chan DnsNotifyRequest
func (app *Application) GetAPIRouter() *mux.Router
```

## Migration Steps

### Phase 1: Prepare TDNS (No Code Movement)

1. **Add Registration APIs to TDNS**
   - Implement `RegisterQueryHandler()`
   - Implement `RegisterNotifyHandler()`
   - Implement `RegisterEngine()`
   - Implement `RegisterAPIRoute()`
   - Add plugin configuration support

2. **Refactor TDNS Initialization**
   - Make TDNS initialization more library-like
   - Expose channels, routers, etc. as public APIs
   - Ensure TDNS can be used as a library

3. **Test TDNS as Library**
   - Create a simple test that uses TDNS as a library
   - Verify all registration APIs work
   - Ensure no KDC/KRS-specific code is required

### Phase 2: Create New Repository

1. **Initialize New Repo**
   ```bash
   mkdir tdns-kms
   cd tdns-kms
   git init
   go mod init github.com/johanix/tdns-kms
   ```

2. **Set up go.mod**
   ```go
   module github.com/johanix/tdns-kms
   
   require (
       github.com/johanix/tdns v0.x.x  // TDNS as dependency
       // ... other dependencies
   )
   ```

3. **Create Directory Structure**
   - Create `cmd/tdns-kdc/` and `cmd/tdns-krs/`
   - Create `kdc/` and `krs/` directories
   - Create `cli/` directory

### Phase 3: Move Code

1. **Move KDC Code**
   - Move all files from `tdns/kdc/` → `tdns-kms/kdc/`
   - Update package declarations: `package kdc` (stays the same)
   - Update imports: `github.com/johanix/tdns/tdns` → `github.com/johanix/tdns/tdns`

2. **Move KRS Code**
   - Move all files from `tdns/krs/` → `tdns-kms/krs/`
   - Update package declarations: `package krs` (stays the same)
   - Update imports: `github.com/johanix/tdns/tdns` → `github.com/johanix/tdns/tdns`

3. **Move CLI Commands**
   - Move `tdns/cli/kdc_cmds.go` → `tdns-kms/cli/kdc_cmds.go`
   - Move `tdns/cli/krs_cmds.go` → `tdns-kms/cli/krs_cmds.go`
   - Update imports and package structure

4. **Create Main Functions**
   - Create `tdns-kms/cmd/tdns-kdc/main.go`:
     ```go
     package main
     
     import (
         "context"
         "github.com/johanix/tdns/tdns"
         "github.com/johanix/tdns-kms/kdc"
         "github.com/johanix/tdns-kms/cli"
     )
     
     func main() {
         // Load TDNS config
         config := tdns.LoadConfig(...)
         
         // Initialize TDNS as library
         app, err := tdns.New(config)
         if err != nil {
             log.Fatal(err)
         }
         
         // Initialize KDC
         kdcDB, kdcConf := kdc.Initialize(...)
         
         // Register KDC handlers with TDNS
         tdns.RegisterQueryHandler(dns.TypeKMREQ, kdc.HandleKdcQuery)
         tdns.RegisterQueryHandler(dns.TypeKMCTRL, kdc.HandleKdcQuery)
         tdns.RegisterNotifyHandler(kdc.HandleKdcNotify)
         tdns.RegisterEngine("KeyStateWorker", kdc.KeyStateWorker)
         tdns.RegisterAPIRoute(app.GetAPIRouter(), "/kdc/zone", kdc.APIKdcZone)
         // ... etc
         
         // Start TDNS
         ctx := context.Background()
         app.Start(ctx)
     }
     ```
   - Create `tdns-kms/cmd/tdns-krs/main.go` similarly

### Phase 4: Update Imports

1. **In New Repo**
   - Update all imports to use TDNS as external dependency
   - Update imports to use new repo paths

2. **In TDNS**
   - Remove all KDC/KRS imports
   - Remove `kdc_init.go` and `krs_init.go`
   - Remove KDC/KRS CLI commands
   - Clean up any KDC/KRS references

### Phase 5: Update Build System

1. **New Repo Build**
   - Create Makefiles for building `tdns-kdc` and `tdns-krs`
   - Update CI/CD to build from new repo

2. **TDNS Build**
   - Remove KDC/KRS from TDNS build targets
   - Update documentation

### Phase 6: Testing and Validation

1. **Unit Tests**
   - Ensure all KDC/KRS tests still pass in new location
   - Update test imports

2. **Integration Tests**
   - Test KDC/KRS using TDNS as library
   - Verify all functionality works

3. **End-to-End Tests**
   - Test full key distribution flow
   - Test blast zone calculation
   - Test all CLI commands

## Files to Move

### From `tdns/kdc/` → `tdns-kms/kdc/`
- `structs.go`
- `db.go`
- `api.go`
- `dns_handler.go`
- `chunks.go`
- `encrypt.go`
- `keygen.go`
- `key_state_worker.go`
- `notify_handler.go`
- `blastzone.go`
- `config.go` (if exists)
- `engine.go` (if exists)
- All test files

### From `tdns/krs/` → `tdns-kms/krs/`
- `structs.go`
- `db.go`
- `api.go`
- `jsonchunk.go`
- `decrypt.go`
- `confirm.go`
- `config.go` (if exists)
- All test files

### From `tdns/cli/` → `tdns-kms/cli/`
- `kdc_cmds.go`
- `krs_cmds.go`

### Files to Remove from TDNS
- `tdns/kdc_init.go` (replaced by new repo's main.go)
- `tdns/krs_init.go` (replaced by new repo's main.go)

### Files to Keep in TDNS
- `tdns/hpke/` - Generic HPKE implementation
- `tdns/code/` - JSONMANIFEST, JSONCHUNK RRtypes (generic)

## Import Path Changes

### Before (in TDNS)
```go
import "github.com/johanix/tdns/tdns/kdc"
import "github.com/johanix/tdns/tdns/krs"
```

### After (in new repo)
```go
import "github.com/johanix/tdns/tdns"        // TDNS as library
import "github.com/johanix/tdns-kms/kdc"     // KDC from new repo
import "github.com/johanix/tdns-kms/krs"     // KRS from new repo
```

## Dependencies

### New Repo Dependencies
- `github.com/johanix/tdns` - TDNS library (protocol implementation)
- All existing KDC/KRS dependencies (gorilla/mux, miekg/dns, etc.)

### TDNS Dependencies
- No changes (removes KDC/KRS dependencies)

## Backward Compatibility

### Breaking Changes
- `tdns-kdc` and `tdns-krs` binaries will be built from new repo
- Import paths change for anyone importing KDC/KRS
- Configuration file structure may change slightly

### Migration Path for Users
1. Update to use new repo for KDC/KRS binaries
2. Update import paths if using KDC/KRS as library
3. Configuration files should be mostly compatible (may need minor updates)

## Benefits

1. **TDNS Purity**: TDNS becomes purely DNS protocol-focused
2. **Clear Separation**: Business logic separated from protocol implementation
3. **Independent Evolution**: KDC/KRS can evolve without affecting TDNS
4. **Easier Onboarding**: New TDNS contributors don't need to understand KDC/KRS
5. **Versioning**: TDNS and KDC/KRS can have independent versioning
6. **Smaller TDNS**: TDNS repository becomes smaller and more focused

## Risks and Mitigations

### Risk: Breaking Existing Deployments
- **Mitigation**: Provide clear migration guide, maintain compatibility where possible

### Risk: Import Path Confusion
- **Mitigation**: Clear documentation, update all examples

### Risk: TDNS API Changes Breaking KDC/KRS
- **Mitigation**: Version TDNS library, use semantic versioning

### Risk: Integration Complexity
- **Mitigation**: Thorough testing, clear registration API design

## Timeline Estimate

- **Phase 1 (TDNS Preparation)**: 1-2 weeks
- **Phase 2 (New Repo Setup)**: 1 day
- **Phase 3 (Code Movement)**: 2-3 days
- **Phase 4 (Import Updates)**: 2-3 days
- **Phase 5 (Build System)**: 1-2 days
- **Phase 6 (Testing)**: 1 week

**Total**: ~3-4 weeks

## Success Criteria

1. ✅ TDNS has no KDC/KRS code or dependencies
2. ✅ TDNS exposes registration APIs for external handlers
3. ✅ New repo builds `tdns-kdc` and `tdns-krs` binaries successfully
4. ✅ All functionality works as before
5. ✅ TDNS can be used as pure DNS protocol library
6. ✅ Documentation updated for both repos

## Open Questions

1. **Repository Name**: `tdns-kms`, `tdns-keymgmt`, or other?
2. **Versioning Strategy**: How to version TDNS library vs. KDC/KRS?
3. **Release Coordination**: How to coordinate releases between repos?
4. **Documentation**: Where does combined documentation live?
5. **CI/CD**: How to test integration between repos?

## Next Steps

1. Finalize repository name and structure
2. Begin Phase 1: Add registration APIs to TDNS
3. Create new repository
4. Execute migration phases systematically
5. Update all documentation

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-XX  
**Status**: Planning Phase

