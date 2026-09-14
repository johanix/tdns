/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"errors"
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

// KeyLifecycleOwner is the state machine that runs the key lifecycle of the
// multi-provider zones it owns: tdns-mp (design §3.5, step S2). tdns keeps
// the keystore, the signing and publishing functions, the DS engine and the
// delegation syncher; for an owned zone it runs none of its own lifecycle
// paths and refuses the API verbs that are lifecycle policy, naming the
// owner's replacement.
//
// A zone is owned exactly when it carries OptMultiProvider, an owner is
// registered, and the owner answers Owns. Registration happens before
// MainInit, so it is in place before any zone's first refresh. With no owner
// registered, or Owns false, a multi-provider zone keeps today's behaviour,
// KeyLifecycleHooks included: that is how the owner rolls out zone by zone.
type KeyLifecycleOwner interface {
	// Name is how tdns names the owner in a refusal.
	Name() string
	// Owns reports whether the owner runs zd's key lifecycle. Asked only for
	// a zone with OptMultiProvider.
	Owns(zd *ZoneData) bool
	// Command names the owner's replacement for one of tdns's lifecycle
	// verbs ("rollover", "clear", "policy-cleanup", "policy-change",
	// "policy-reset", "asap", "cancel", "reset", "unstick", "setstate",
	// "alg-rollover"), for the refusal.
	Command(verb string) string
	// DSIntent is the owner's answer to "which DS should the parent hold" for
	// a zone it owns (§4). Known false leaves the parent alone.
	DSIntent(zd *ZoneData, digest uint8) (DSIntent, error)
}

// ErrZoneOwned is in every refusal of a lifecycle verb on an owned zone.
var ErrZoneOwned = errors.New("the zone's key lifecycle is owned")

var (
	keyLifecycleOwnerMu sync.RWMutex
	keyLifecycleOwner   KeyLifecycleOwner
)

// RegisterKeyLifecycleOwner installs o, replacing whatever was registered
// before; nil clears it. Register before MainInit.
func RegisterKeyLifecycleOwner(o KeyLifecycleOwner) {
	keyLifecycleOwnerMu.Lock()
	defer keyLifecycleOwnerMu.Unlock()
	keyLifecycleOwner = o
}

func currentKeyLifecycleOwner() KeyLifecycleOwner {
	keyLifecycleOwnerMu.RLock()
	defer keyLifecycleOwnerMu.RUnlock()
	return keyLifecycleOwner
}

// zoneOwned is the ownership test: OptMultiProvider, an owner, and its
// answer. Every lifecycle path and every refused verb asks it.
func zoneOwned(zd *ZoneData) bool {
	if zd == nil || !zd.Options[OptMultiProvider] {
		return false
	}
	o := currentKeyLifecycleOwner()
	return o != nil && o.Owns(zd)
}

// zoneOwnedByName is zoneOwned for the keystore functions, which are keyed
// by zone name; a zone that is not loaded is not owned.
func zoneOwnedByName(zone string) (*ZoneData, bool) {
	zd, ok := Zones.Get(dns.Fqdn(zone))
	if !ok || zd == nil {
		return nil, false
	}
	return zd, zoneOwned(zd)
}

// ownedRefusal is the error a lifecycle verb returns on an owned zone: it
// names the owner and the owner's command for the verb.
func ownedRefusal(zd *ZoneData, verb string) error {
	o := currentKeyLifecycleOwner()
	name, cmd := "its owner", ""
	if o != nil {
		name, cmd = o.Name(), o.Command(verb)
	}
	if cmd == "" {
		return fmt.Errorf("%w: zone %s: %s runs its key lifecycle, not tdns", ErrZoneOwned, zd.ZoneName, name)
	}
	return fmt.Errorf("%w: zone %s: %s runs its key lifecycle; use `%s`", ErrZoneOwned, zd.ZoneName, name, cmd)
}
