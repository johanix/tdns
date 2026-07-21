/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The peers: block (docs/2026-07-21-peers-xfr-auth-design.md): one
 * declaration per remote server, referenced from the four peer/ACL lists as
 * `- peers: [ id, ... ]` entries. Everything here is parse-time — references
 * expand into the existing PeerConf/AclEntry structures, so the runtime
 * (resolvePrimaries, refresh engine, ACL matcher) is untouched. This file
 * also implements the transfer-terminology alias normalization
 * (upstreams:/request-xfr: -> primaries; secondaries:/provide-xfr: ->
 * downstreams).
 */
package tdns

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strings"
)

// TLSIdentity describes how WE verify a peer's CLIENT certificate when it
// connects to us (the downstream role). Data-driven: whichever credentials
// are present determine which downstream-auth mechanisms this peer CAN
// satisfy (pins -> tls-pin, ca-file -> tls-pkix, dane -> tls-dane); which of
// those SUFFICE is the zone's downstream-auth decision.
type TLSIdentity struct {
	// Name is the identity pin: the tls-pkix mechanism requires the client
	// leaf to carry this DNS SAN, and tls-dane uses it as the TLSA base.
	// Defaults to the host part of the peer's addr. Chain-only semantics
	// (any member of the CA) apply only when no name exists at all.
	Name string `yaml:"name" mapstructure:"name"`
	// Pins are base64 SPKI SHA-256 digests (any match satisfies tls-pin).
	Pins []string `yaml:"pins" mapstructure:"pins"`
	// CAFile holds TRUST ANCHORS ONLY — root cert(s), concatenated PEM;
	// never intermediates (those arrive in the client's presented chain),
	// never the leaf.
	CAFile string `yaml:"ca-file" mapstructure:"ca-file"`
	// Dane enables the tls-dane mechanism: the presented client cert must
	// match Name's DNSSEC-validated TLSA RRset.
	Dane bool `yaml:"dane" mapstructure:"dane"`
}

// PeerDef is one entry in the top-level peers: block — a superset of
// PeerConf: the outbound fields (how we dial and verify the peer's server
// cert) map 1:1, plus the inbound side (prefixes its requests come from and
// the tls-identity its client cert must prove).
type PeerDef struct {
	// Outbound (upstream/notify roles).
	Addr      string   `yaml:"addr" mapstructure:"addr"`
	Key       string   `yaml:"key" mapstructure:"key"`   // sugar for keys: [x]
	Keys      []string `yaml:"keys" mapstructure:"keys"` // sign with FIRST, accept ANY inbound
	Transport string   `yaml:"transport" mapstructure:"transport"`
	TLSAuth   string   `yaml:"tls-auth" mapstructure:"tls-auth"`
	TLSName   string   `yaml:"tls-name" mapstructure:"tls-name"`
	Pins      []string `yaml:"pins" mapstructure:"pins"`
	CAFile    string   `yaml:"ca-file" mapstructure:"ca-file"`
	// Inbound (downstream/allow-notify roles).
	Prefixes    []string     `yaml:"prefixes" mapstructure:"prefixes"` // default: addr's host
	TLSIdentity *TLSIdentity `yaml:"tls-identity" mapstructure:"tls-identity"`
}

// peerAddrHost returns the host part of the peer's addr ("" if unset).
func (p *PeerDef) addrHost() string {
	if p.Addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(p.Addr); err == nil {
		return h
	}
	return p.Addr
}

// ValidatePeers validates and normalizes the peers: block in place:
// key/keys sugar resolution, NOKEY-alone rule, prefix and tls-identity name
// defaulting, outbound validation via validatePeerXoT, inbound credential
// validation. A broken peer definition does NOT abort the config — it is
// recorded and every zone referencing it is quarantined at expansion time
// (matching the quarantine-zones-not-abort house rule; one typo must not
// take the whole server down). Returns the broken map (peer id -> reason).
func (conf *Config) ValidatePeers() map[string]string {
	broken := map[string]string{}
	for id, p := range conf.Peers {
		if err := validatePeerDef(&p); err != nil {
			lgConfig.Error("peers: invalid peer definition; zones referencing it will be quarantined", "peer", id, "err", err)
			broken[id] = err.Error()
			continue
		}
		conf.Peers[id] = p // store the normalized copy
	}
	return broken
}

func validatePeerDef(p *PeerDef) error {
	// key: is sugar for keys: [x]; both set is ambiguous.
	if p.Key != "" && len(p.Keys) > 0 {
		return fmt.Errorf("both key and keys set (key: %q is sugar for keys: [%q]; use one)", p.Key, p.Key)
	}
	if p.Key != "" {
		p.Keys = []string{p.Key}
		p.Key = ""
	}
	if len(p.Keys) == 0 {
		return fmt.Errorf("no TSIG key (use keys: [NOKEY] for no TSIG)")
	}
	// NOKEY only alone: mixing it with named keys would recreate the
	// NOKEY-shadows-TSIG footgun inside a single object.
	for _, k := range p.Keys {
		if k == NOKEY && len(p.Keys) > 1 {
			return fmt.Errorf("NOKEY must be the only entry in keys (mixing it with named keys disables TSIG for this peer)")
		}
		if k == "" {
			return fmt.Errorf("empty key name in keys")
		}
	}

	// Outbound: validate exactly like an inline upstream entry (only
	// meaningful when the peer has a dial target).
	if p.Addr != "" {
		pc := PeerConf{
			Addr:      p.Addr,
			Key:       p.Keys[0],
			Transport: p.Transport,
			TLSAuth:   p.TLSAuth,
			TLSName:   p.TLSName,
			Pins:      p.Pins,
			CAFile:    p.CAFile,
		}
		if err := validatePeerXoT(&pc); err != nil {
			return err
		}
		// validatePeerXoT normalizes transport/tls-auth; keep that.
		p.Transport, p.TLSAuth = pc.Transport, pc.TLSAuth
	} else if p.Transport != "" || p.TLSAuth != "" || p.TLSName != "" || len(p.Pins) > 0 || p.CAFile != "" {
		return fmt.Errorf("outbound TLS fields (transport/tls-auth/...) require addr")
	}

	// Inbound prefixes: default from addr's host (exact address).
	if len(p.Prefixes) == 0 {
		if host := p.addrHost(); host != "" && net.ParseIP(host) != nil {
			p.Prefixes = []string{host}
		}
		// A hostname addr yields no prefix default — inbound use then
		// requires explicit prefixes (checked at reference time).
	}

	if ti := p.TLSIdentity; ti != nil {
		if ti.Name == "" {
			if host := p.addrHost(); host != "" && net.ParseIP(host) == nil {
				ti.Name = host
			}
		}
		for _, pin := range ti.Pins {
			raw, err := base64.StdEncoding.DecodeString(pin)
			if err != nil || len(raw) != sha256.Size {
				return fmt.Errorf("tls-identity pin %q is not a base64 SHA-256 SPKI digest", pin)
			}
		}
		if ti.CAFile != "" {
			if err := checkPEMCertFile(ti.CAFile); err != nil {
				return fmt.Errorf("tls-identity ca-file %q: %v", ti.CAFile, err)
			}
		}
		if ti.Dane && ti.Name == "" {
			return fmt.Errorf("tls-identity dane requires a name (none given, and addr provides no hostname)")
		}
		if len(ti.Pins) == 0 && ti.CAFile == "" && !ti.Dane {
			return fmt.Errorf("tls-identity is empty (give pins, ca-file, or dane: true)")
		}
	}
	return nil
}

// expandPeerRefs replaces every `- peers: [ id, ... ]` reference entry in the
// zone's four lists with the expansion of the named peers. Called after
// template expansion (so templates may carry references) and before the
// per-zone validation that consumes the lists. An error quarantines the zone.
func (conf *Config) expandPeerRefs(zconf *ZoneConf, brokenPeers map[string]string) error {
	var err error
	if zconf.Primaries, err = conf.expandPeerList(zconf.Primaries, "upstreams", brokenPeers); err != nil {
		return err
	}
	if zconf.Notify, err = conf.expandPeerList(zconf.Notify, "notify", brokenPeers); err != nil {
		return err
	}
	if zconf.Downstreams, err = conf.expandAclList(zconf.Downstreams, "downstreams", true, brokenPeers); err != nil {
		return err
	}
	if zconf.AllowNotify, err = conf.expandAclList(zconf.AllowNotify, "allow-notify", false, brokenPeers); err != nil {
		return err
	}
	return nil
}

// lookupPeer resolves one reference id, distinguishing unknown ids (with a
// hint about the legacy bare-string shape) from known-but-broken peers.
func (conf *Config) lookupPeer(id, where string, brokenPeers map[string]string) (PeerDef, error) {
	if reason, bad := brokenPeers[id]; bad {
		return PeerDef{}, fmt.Errorf("%s: peer %q is invalid: %s", where, id, reason)
	}
	p, ok := conf.Peers[id]
	if !ok {
		return PeerDef{}, fmt.Errorf("%s: unknown peer %q (not in the peers: block)", where, id)
	}
	return p, nil
}

// expandPeerList expands references inside an upstreams:/notify: list into
// outbound PeerConf entries (signing key = keys[0]).
func (conf *Config) expandPeerList(in []PeerConf, where string, brokenPeers map[string]string) ([]PeerConf, error) {
	out := make([]PeerConf, 0, len(in))
	for _, e := range in {
		if len(e.PeersRef) == 0 {
			out = append(out, e)
			continue
		}
		if e.Addr != "" || e.Key != "" {
			return nil, fmt.Errorf("%s: an entry may be a reference (peers:) or inline (addr/key), not both", where)
		}
		for _, id := range e.PeersRef {
			p, err := conf.lookupPeer(id, where, brokenPeers)
			if err != nil {
				return nil, err
			}
			if p.Addr == "" {
				return nil, fmt.Errorf("%s: peer %q has no addr and cannot be dialed", where, id)
			}
			out = append(out, PeerConf{
				Addr:      p.Addr,
				Key:       p.Keys[0],
				Transport: p.Transport,
				TLSAuth:   p.TLSAuth,
				TLSName:   p.TLSName,
				Pins:      p.Pins,
				CAFile:    p.CAFile,
			})
		}
	}
	return out, nil
}

// expandAclList expands references inside a downstreams:/allow-notify: list
// into the prefix x key cross-product of AclEntries — the same shape the
// hand-written TSIG-rollover pattern produces, so the ACL matcher is
// untouched. Only downstreams entries carry the peer's tls-identity
// (allow-notify is Do53 NOTIFY; certificates play no role there).
func (conf *Config) expandAclList(in []AclEntry, where string, withIdentity bool, brokenPeers map[string]string) ([]AclEntry, error) {
	out := make([]AclEntry, 0, len(in))
	for _, e := range in {
		if len(e.PeersRef) == 0 {
			out = append(out, e)
			continue
		}
		if e.Prefix != "" || e.Key != "" {
			return nil, fmt.Errorf("%s: an entry may be a reference (peers:) or inline (prefix/key), not both", where)
		}
		for _, id := range e.PeersRef {
			p, err := conf.lookupPeer(id, where, brokenPeers)
			if err != nil {
				return nil, err
			}
			if len(p.Prefixes) == 0 {
				return nil, fmt.Errorf("%s: peer %q has no prefixes (and addr provides no IP) — cannot be matched as a source", where, id)
			}
			for _, prefix := range p.Prefixes {
				for _, key := range p.Keys {
					ae := AclEntry{Prefix: prefix, Key: key, PeerName: id}
					if withIdentity {
						ae.TLSIdentity = p.TLSIdentity
					}
					out = append(out, ae)
				}
			}
		}
	}
	return out, nil
}

// --- transfer-terminology aliases -------------------------------------------

// xfrKeyAliases maps every accepted spelling to the canonical (internal) key.
// BIND9: primaries/secondaries. tdns (canonical in docs): upstreams/
// downstreams. NSD: request-xfr/provide-xfr.
var xfrKeyAliases = map[string]string{
	"upstreams":   "primaries",
	"request-xfr": "primaries",
	"secondaries": "downstreams",
	"provide-xfr": "downstreams",
}

// NormalizeXfrAliases rewrites alias spellings in every zones:/templates:
// entry of the raw config map to the canonical keys, BEFORE mapstructure
// decoding (so aliases neither fail to decode nor show up as unknown keys).
// Two spellings of the same field in one entry is a conflict: never a silent
// preference — the entry's name is recorded and the zone is quarantined by
// ParseZones. Returns conflicts as map[zone-or-template name]description.
func NormalizeXfrAliases(configMap map[string]interface{}) map[string]string {
	conflicts := map[string]string{}
	for _, section := range []string{"zones", "templates"} {
		list, ok := configMap[section].([]interface{})
		if !ok {
			continue
		}
		for _, item := range list {
			entry := asStringMap(item)
			if entry == nil {
				continue
			}
			name, _ := entry["name"].(string)
			for _, alias := range aliasKeysSorted() {
				canonical := xfrKeyAliases[alias]
				val, present := entry[alias]
				if !present {
					continue
				}
				if _, clash := entry[canonical]; clash {
					conflicts[name] = fmt.Sprintf("%s: both %q and %q given — use one spelling", section, alias, canonical)
					continue
				}
				entry[canonical] = val
				delete(entry, alias)
			}
		}
	}
	return conflicts
}

// aliasKeysSorted returns the alias spellings in deterministic order so a
// double-alias conflict (e.g. upstreams + request-xfr) reports stably.
func aliasKeysSorted() []string {
	keys := make([]string, 0, len(xfrKeyAliases))
	for k := range xfrKeyAliases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// asStringMap normalizes the two map shapes YAML decoding can produce.
func asStringMap(v interface{}) map[string]interface{} {
	switch m := v.(type) {
	case map[string]interface{}:
		return m
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			if ks, ok := k.(string); ok {
				out[ks] = val
			}
		}
		return out
	default:
		return nil
	}
}

// aliasConflictFor returns the recorded alias conflict for a zone or
// template name ("" if none). Case: zone names in config may lack the
// trailing dot; check both forms.
func aliasConflictFor(conflicts map[string]string, name string) string {
	if c, ok := conflicts[name]; ok {
		return c
	}
	if c, ok := conflicts[strings.TrimSuffix(name, ".")]; ok {
		return c
	}
	return ""
}
