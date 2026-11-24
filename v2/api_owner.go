/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * API owners: who may manage a zone or a key over the management API.
 * Design: docs/2026-11-23-tdns-api-ownership-design.md sections 4.1, 4.3,
 * 4.4 and 4.8. Owners are recorded and shown; nothing is refused because of
 * one yet.
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The API owners (design 4.1). "API owner", not "owner", in everything an
// operator reads: a zone's owner is its registrant in the multi-provider
// work, and an owner name is a DNS name.
const (
	// ApiOwnerConfig: from the static config, managed by editing it.
	ApiOwnerConfig = "config"
	// ApiOwnerApi: created over the API by a caller with no name (the local
	// socket, the API key, a path inside the daemon); managed by operators.
	ApiOwnerApi = "api"
	// ApiOwnerCertPrefix, followed by an access-file client name: created
	// by, or handed to, that certificate client.
	ApiOwnerCertPrefix = "cert:"
	// ApiOwnerNoZone is the API owner column of a SIG(0) or DNSSEC key
	// whose zone is not served here (design 4.4).
	ApiOwnerNoZone = "-"
)

// ApiOwner is the API owner this caller records on what it creates. Only a
// certificate names its caller; the socket and the API key are "api".
func (id ApiIdentity) ApiOwner() string {
	if id.Via == ApiViaCertificate && id.Name != "" {
		return ApiOwnerCertPrefix + id.Name
	}
	return ApiOwnerApi
}

// CallerApiOwner is the API owner the caller of a management API request
// records: that of the identity the auth middleware put on ctx. A context
// without one is a path inside the daemon, which records "api".
func CallerApiOwner(ctx context.Context) string {
	if id, ok := ApiIdentityFrom(ctx); ok {
		return id.ApiOwner()
	}
	return ApiOwnerApi
}

// ApiOwnerClient returns the client name of a "cert:<name>" API owner.
func ApiOwnerClient(owner string) (string, bool) {
	return strings.CutPrefix(owner, ApiOwnerCertPrefix)
}

func checkCertApiOwner(owner string) error {
	name, _ := ApiOwnerClient(owner)
	if err := CheckAccessClientName(name); err != nil {
		return fmt.Errorf("API owner %q: %v", owner, err)
	}
	return nil
}

// StaticApiOwner is the API owner of a config-file zone whose api-owner: is
// v: "config" when unset. A zone there belongs to the config or to a
// certificate client the operator hands it to; "api" is what an operator's
// API call records, never a config-file setting.
func StaticApiOwner(v string) (string, error) {
	switch {
	case v == "" || v == ApiOwnerConfig:
		return ApiOwnerConfig, nil
	case strings.HasPrefix(v, ApiOwnerCertPrefix):
		if err := checkCertApiOwner(v); err != nil {
			return "", fmt.Errorf("api-owner: %v", err)
		}
		return v, nil
	}
	return "", fmt.Errorf("api-owner: %q is not an API owner a config-file zone can have (config, the default, or cert:<name>)", v)
}

// CheckSettableApiOwner checks an API owner `zone setowner` may give a zone:
// "api", which hands it back to the operators, or "cert:<name>".
func CheckSettableApiOwner(v string) error {
	switch {
	case v == ApiOwnerApi:
		return nil
	case strings.HasPrefix(v, ApiOwnerCertPrefix):
		return checkCertApiOwner(v)
	}
	return fmt.Errorf("API owner %q: use api or cert:<name>", v)
}

// dynamicApiOwner is the API owner of an entry in the dynamic config: "api"
// when it has none (written before owners were recorded). A value the daemon
// would not have written is reported and read as "api", so that a damaged
// entry hands its zone to no certificate client.
func dynamicApiOwner(v string) (string, error) {
	if v == "" {
		return ApiOwnerApi, nil
	}
	if err := CheckSettableApiOwner(v); err != nil {
		return ApiOwnerApi, err
	}
	return v, nil
}

// recordedApiOwner is the API owner the zone itself records: "" for a
// catalog member, which follows its catalog zone.
func (zd *ZoneData) recordedApiOwner() string {
	if p := zd.apiOwner.Load(); p != nil {
		return *p
	}
	return ""
}

func (zd *ZoneData) setApiOwner(owner string) {
	zd.apiOwner.Store(&owner)
}

// maxCatalogHops bounds the walk from a catalog member to the zone that
// records its owner. A member is not a catalog of its own, but a damaged
// dynamic config must not make the walk loop.
const maxCatalogHops = 4

// EffectiveApiOwner is who may manage the zone over the management API
// (design 4.3): the owner the zone records or, for a catalog member, its
// catalog zone's, looked up on every call so that a new owner of the catalog
// zone is its members' too. A member whose catalog zone is not served here
// is "api": operators manage it. A zone that records none is "config" when
// the config file defines it and "api" otherwise.
func (zd *ZoneData) EffectiveApiOwner() string {
	z := zd
	for range maxCatalogHops {
		// A member the config file has since taken over is the config's.
		if z.SourceCatalog == "" || z.fromStaticConfig.Load() {
			if o := z.recordedApiOwner(); o != "" {
				return o
			}
			if z.fromStaticConfig.Load() {
				return ApiOwnerConfig
			}
			return ApiOwnerApi
		}
		cat, ok := Zones.Get(z.SourceCatalog)
		if !ok || cat == nil {
			return ApiOwnerApi
		}
		z = cat
	}
	return ApiOwnerApi
}

// ZoneApiOwner is the effective API owner of the zone named name, and
// whether this server serves it. A SIG(0) or DNSSEC key belongs to its zone
// and has the zone's owner (design 4.4); a key whose zone is not served here
// has none, and is the admin's alone.
func ZoneApiOwner(name string) (string, bool) {
	zd, ok := Zones.Get(core.CanonicalizeName(dns.Fqdn(name)))
	if !ok || zd == nil {
		return "", false
	}
	return zd.EffectiveApiOwner(), true
}

// keystoreApiOwner is the API owner column of a SIG(0) or DNSSEC key row.
func keystoreApiOwner(zone string) string {
	if o, ok := ZoneApiOwner(zone); ok {
		return o
	}
	return ApiOwnerNoZone
}

// apiOwnerFixedBy says why `zone setowner` may not change zd's API owner,
// or "" when it may. Only a zone created over the API (zone add, catalog
// create) takes its owner from setowner: a config-file zone's is in its
// config, and a catalog member has its catalog zone's.
func (zd *ZoneData) apiOwnerFixedBy() string {
	name := zd.ZoneName
	switch {
	case zd.fromStaticConfig.Load():
		return fmt.Sprintf("zone %s: a config-file zone; set api-owner: in its config", name)
	case zd.SourceCatalog != "":
		return fmt.Sprintf("zone %s: a member of catalog zone %s, whose API owner it has", name, zd.SourceCatalog)
	case zd.Options[OptApiManagedZone], zd.Options[OptCatalogZone]:
		return ""
	}
	return fmt.Sprintf("zone %s: not created over the API; its API owner is fixed", name)
}

// SetZoneApiOwner is the `zone setowner` core (design 4.8): it hands a zone
// created over the API to a certificate client, or back to the operators
// ("api"). The new owner is in the dynamic config before it is reported; a
// failed write leaves the zone as it was. The warnings are for the operator:
// an owner that no client of the running access file has.
func (conf *Config) SetZoneApiOwner(name, owner string) (msg string, warnings []string, err error) {
	name = core.CanonicalizeName(dns.Fqdn(name))
	if err := CheckSettableApiOwner(owner); err != nil {
		return "", nil, err
	}
	// As modify and delete hold it: both replace the zone's ZoneData, and an
	// owner set on the one being replaced would be lost.
	templateApplyMu.Lock()
	defer templateApplyMu.Unlock()
	zd, ok := Zones.Get(name)
	if !ok || zd == nil {
		return "", nil, fmt.Errorf("zone %s not found", name)
	}
	if why := zd.apiOwnerFixedBy(); why != "" {
		return "", nil, errors.New(why)
	}
	warnings = conf.apiOwnerClientWarnings(owner)
	old := zd.EffectiveApiOwner()
	if old == owner {
		return fmt.Sprintf("zone %s: API owner already %s", name, owner), warnings, nil
	}
	prev := zd.apiOwner.Load()
	zd.setApiOwner(owner)
	if err := conf.AddDynamicZoneToConfig(zd); err != nil {
		zd.apiOwner.Store(prev)
		return "", nil, fmt.Errorf("zone %s: API owner unchanged: the dynamic config could not be written: %w", name, err)
	}
	lgApi.Info("zone API owner changed", "zone", name, "from", old, "to", owner)
	return fmt.Sprintf("zone %s: API owner %s (was %s)", name, owner, old), warnings, nil
}

// apiOwnerClientWarnings warns when owner names a certificate client the
// running access file does not have. The owner is set anyway: a client may
// be enrolled after its zones are handed over. But a misspelt name hands
// the zone to nobody, and this is where the operator can see it.
func (conf *Config) apiOwnerClientWarnings(owner string) []string {
	name, ok := ApiOwnerClient(owner)
	if !ok {
		return nil
	}
	st := conf.Internal.ApiAccess.load()
	if st == nil || !st.Enabled || st.Err != nil {
		return nil
	}
	for _, c := range st.Clients {
		if c.Name == name {
			return nil
		}
	}
	return []string{fmt.Sprintf("the access file has no client %q", name)}
}

// inputApiOwner is a caller's API owner as an internal path passes it:
// empty is "api", as for a request with no identity.
func inputApiOwner(owner string) string {
	if owner == "" {
		return ApiOwnerApi
	}
	return owner
}
