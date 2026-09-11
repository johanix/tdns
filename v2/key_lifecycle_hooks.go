/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"errors"
	"sync"

	"github.com/miekg/dns"
)

// KeyLifecycleHooks lets a derived application steer the lifecycle of the
// DNSSEC keys tdns keeps in DnssecKeyStore, without tdns learning what the
// application's key states mean. Registered once, in the style of the zone
// option handlers, before tdns's MainInit. Every field is optional: a nil hook
// means the behaviour tdns has always had, which is what every zone gets when
// nothing is registered.
//
// tdns attaches no meaning to a state a hook names beyond what it already
// does with every state: FetchZoneDnskeysSql decides which states are served
// in the DNSKEY RRset, loadDnssecKeysFromDB(..., active) decides which keys
// sign, and the worker's walks decide which states move on a timer. A hook
// that stages keys into a state of its own therefore also owns the transition
// out of it.
type KeyLifecycleHooks struct {
	// StagedState is the state a newly generated standby key starts in:
	// "published" by default. Keys in this state count as "in the pipeline"
	// for standby maintenance, so no second key is minted while one waits
	// there.
	StagedState func(zd *ZoneData) string
	// RetiredState is the state a retired key moves to once its removal
	// margin has passed: "removed" by default.
	RetiredState func(zd *ZoneData) string
	// MayPromote reports whether a published key may become active now, when
	// EnsureActiveDnssecKeys finds no active key of its role. Default: yes.
	MayPromote func(zd *ZoneData, keyid uint16) bool
	// MayGenerate reports whether EnsureActiveDnssecKeys may mint a key of this
	// role ("KSK" or "ZSK") because the active set is short. Default: yes. A
	// refusal is ErrKeyGenerationDeferred, which the publish path reads as
	// "not yet" on a zone that has not served a signed version: it publishes
	// unsigned and stays not Ready, exactly as it does before the policy
	// binds. When generation IS allowed the key is generated active, as it
	// always has been; StagedState is not on this path.
	MayGenerate func(zd *ZoneData, role string) bool
	// OnStateChange runs after every committed state change of a DNSKEY:
	// UpdateDnssecKeyState, PromoteDnssecKey, and a GenerateKeypair that owns
	// its transaction (from is "" for a new key). It runs on the caller's
	// goroutine after the commit; it must not block on the caller.
	OnStateChange func(zone string, keyid uint16, from, to string)
}

// ErrKeyGenerationDeferred reports that EnsureActiveDnssecKeys found no active
// key of a role, and the registered MayGenerate hook refused to mint one: a key
// of that role exists in a state the hooks' owner has not released yet. Not a
// fault. See KeyLifecycleHooks.MayGenerate for how the publish path reads it.
var ErrKeyGenerationDeferred = errors.New("key generation deferred: a key of this role exists and is not active yet")

var (
	keyLifecycleHooksMu sync.RWMutex
	keyLifecycleHooks   KeyLifecycleHooks
)

// RegisterKeyLifecycleHooks installs h, replacing whatever was registered
// before. Register before MainInit, so the hooks are in place before any
// zone's first refresh; registering the zero value restores the defaults.
func RegisterKeyLifecycleHooks(h KeyLifecycleHooks) {
	keyLifecycleHooksMu.Lock()
	defer keyLifecycleHooksMu.Unlock()
	keyLifecycleHooks = h
}

func currentKeyLifecycleHooks() KeyLifecycleHooks {
	keyLifecycleHooksMu.RLock()
	defer keyLifecycleHooksMu.RUnlock()
	return keyLifecycleHooks
}

// zoneForKeyHooks finds the loaded zone a keystore row belongs to. The
// keystore functions are keyed by zone name; the hooks want the zone. A zone
// that is not loaded gets the defaults.
func zoneForKeyHooks(zone string) *ZoneData {
	zd, ok := Zones.Get(dns.Fqdn(zone))
	if !ok {
		return nil
	}
	return zd
}

// keyStagedStateFor is the state a newly generated standby key of zone starts
// in: the StagedState hook's answer, or "published".
func keyStagedStateFor(zone string) string {
	h := currentKeyLifecycleHooks()
	if h.StagedState == nil {
		return DnskeyStatePublished
	}
	zd := zoneForKeyHooks(zone)
	if zd == nil {
		return DnskeyStatePublished
	}
	if s := h.StagedState(zd); s != "" {
		return s
	}
	return DnskeyStatePublished
}

// keyRetiredStateFor is the state a retired key of zone moves to once its
// margin has passed: the RetiredState hook's answer, or "removed".
func keyRetiredStateFor(zone string) string {
	h := currentKeyLifecycleHooks()
	if h.RetiredState == nil {
		return DnskeyStateRemoved
	}
	zd := zoneForKeyHooks(zone)
	if zd == nil {
		return DnskeyStateRemoved
	}
	if s := h.RetiredState(zd); s != "" {
		return s
	}
	return DnskeyStateRemoved
}

func keyMayPromote(zd *ZoneData, keyid uint16) bool {
	h := currentKeyLifecycleHooks()
	if h.MayPromote == nil || zd == nil {
		return true
	}
	return h.MayPromote(zd, keyid)
}

func keyMayGenerate(zd *ZoneData, role string) bool {
	h := currentKeyLifecycleHooks()
	if h.MayGenerate == nil || zd == nil {
		return true
	}
	return h.MayGenerate(zd, role)
}

func notifyKeyStateChange(zone string, keyid uint16, from, to string) {
	h := currentKeyLifecycleHooks()
	if h.OnStateChange == nil {
		return
	}
	h.OnStateChange(dns.Fqdn(zone), keyid, from, to)
}
