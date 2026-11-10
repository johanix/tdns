/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// TSIG grants: what a TSIG key may change in a zone over RFC 2136 UPDATE.
//
// A SIG(0) key is opted in to updating a zone through the truststore, and
// updatepolicy.zone then scopes it by deriving the permitted names from the
// signer's own name (self/selfsub). A TSIG key is a shared secret that is
// usually configured for something else -- a transfer, a NOTIFY -- so it gets
// no update rights from being configured. It gets them only from a grant that
// names it, in the zone's updatepolicy.zone.tsig list:
//
//	updatepolicy:
//	  zone:
//	    tsig:
//	      - { key: ddns-key.,    nametype: zonesub,   rrtypes: [ ANY ] }
//	      - { key: acme-key.,    nametype: subdomain, name: _acme-challenge.example., rrtypes: [ TXT ] }
//	      - { key: host1.example., nametype: self,    rrtypes: [ A, AAAA, TXT ] }
//
// The name types are a subset of BIND's update-policy, with BIND's names:
//
//	zonesub    anywhere in the zone
//	subdomain  name, or anything below it (name must be in the zone)
//	name       exactly name
//	self       exactly the key's own name
//
// A record may be changed when some grant names the key, covers the owner and
// covers the type. There are no deny rules, so the order of the grants does
// not matter, and no wildcard key: "*" is refused, so that a key configured
// for transfers can never become an update key by accident.
//
// The admission switch is the zone option allow-tsig-updates, separate from
// allow-updates (SIG(0)) and allow-api-updates (the management API).

// TSIG grant name types.
const (
	TsigNameZonesub   = "zonesub"
	TsigNameSubdomain = "subdomain"
	TsigNameName      = "name"
	TsigNameSelf      = "self"
)

// TsigGrantConf is one entry of updatepolicy.zone.tsig, as configured.
type TsigGrantConf struct {
	Key      string   `yaml:"key" mapstructure:"key"`
	NameType string   `yaml:"nametype" mapstructure:"nametype"`
	Name     string   `yaml:"name,omitempty" mapstructure:"name"`
	RRtypes  []string `yaml:"rrtypes" mapstructure:"rrtypes"`
}

// TsigGrant is a parsed, validated TsigGrantConf. Names are canonical FQDNs.
type TsigGrant struct {
	Key      string
	NameType string
	// Name is the name the name type needs: the zone apex for zonesub, the
	// configured name for subdomain and name, empty for self.
	Name    string
	RRtypes map[uint16]bool
	// Any is set when rrtypes lists ANY: every type outside tsigAnyExcluded.
	Any bool
}

// tsigAnyExcluded is what ANY in a TSIG grant does NOT cover ("narrow ANY").
// These are the types that make the zone what it is, or that drive its DNSSEC
// and its delegation: the serial (tdns owns it), the zone's keys and their
// signatures and denial records, the CDS/CDNSKEY/CSYNC signals that change the
// delegation at the parent, and the zone digest. A key that should change one
// of them must have it listed by name. BIND's ANY covers all of them except
// NSEC and NSEC3; a key handed out for host addresses or ACME challenges should
// not be able to replace a zone's DNSKEY or move its DS.
var tsigAnyExcluded = map[uint16]bool{
	dns.TypeSOA:        true,
	dns.TypeDNSKEY:     true,
	dns.TypeRRSIG:      true,
	dns.TypeNSEC:       true,
	dns.TypeNSEC3:      true,
	dns.TypeNSEC3PARAM: true,
	dns.TypeCDS:        true,
	dns.TypeCDNSKEY:    true,
	dns.TypeCSYNC:      true,
	dns.TypeZONEMD:     true,
}

// canonicalFqdn is the form grant keys and names are kept and compared in:
// fully qualified, ASCII-lowercased (core.CanonicalizeName, which leaves
// non-ASCII octets alone so distinct names stay distinct).
func canonicalFqdn(name string) string {
	return core.CanonicalizeName(dns.Fqdn(strings.TrimSpace(name)))
}

func (g TsigGrant) keyMatches(key string) bool { return g.Key == canonicalFqdn(key) }

func (g TsigGrant) coversOwner(owner string) bool {
	o := canonicalFqdn(owner)
	switch g.NameType {
	case TsigNameZonesub, TsigNameSubdomain:
		return dns.IsSubDomain(g.Name, o)
	case TsigNameName:
		return o == g.Name
	case TsigNameSelf:
		return o == g.Key
	}
	return false
}

// coversType: an explicitly listed type, or anything ANY covers. TYPE ANY in
// an update (a DELNAME, RFC 2136 §2.5.3) needs a grant of ANY; what it then
// deletes is filtered type by type in the applier.
func (g TsigGrant) coversType(t uint16) bool {
	if t == dns.TypeANY {
		return g.Any
	}
	if g.RRtypes[t] {
		return true
	}
	return g.Any && !tsigAnyExcluded[t]
}

// tsigGrantsAllow reports whether some grant lets key change owner's rrtype.
func tsigGrantsAllow(grants []TsigGrant, key, owner string, rrtype uint16) bool {
	for _, g := range grants {
		if g.keyMatches(key) && g.coversOwner(owner) && g.coversType(rrtype) {
			return true
		}
	}
	return false
}

// evalTsigGrants decides one record of a TSIG-authorized UPDATE. On refusal it
// says why, as the EDE the response carries: the key has no grant in this zone
// at all, a grant covers the owner but not the type, or no grant of the key's
// covers the owner.
func evalTsigGrants(grants []TsigGrant, key string, rr dns.RR) (bool, uint16) {
	owner, rrtype := rr.Header().Name, rr.Header().Rrtype
	if tsigGrantsAllow(grants, key, owner, rrtype) {
		return true, 0
	}
	keyHasGrant, ownerCovered := false, false
	for _, g := range grants {
		if !g.keyMatches(key) {
			continue
		}
		keyHasGrant = true
		if g.coversOwner(owner) {
			ownerCovered = true
		}
	}
	switch {
	case !keyHasGrant:
		return false, edns0.EDEZoneUpdatesNotAllowed
	case ownerCovered:
		return false, edns0.EDEZoneUpdateRRtypeNotAllowed
	default:
		return false, edns0.EDEZoneUpdateOwnerOutsidePolicy
	}
}

// parseTsigGrants validates a zone's updatepolicy.zone.tsig. A grant that
// cannot mean what it says is refused rather than dropped: unlike the SIG(0)
// rrtype list, which skips names it does not know, a TSIG grant that silently
// lost a type would refuse updates its operator believes are allowed.
func parseTsigGrants(zone string, confs []TsigGrantConf) ([]TsigGrant, error) {
	apex := canonicalFqdn(zone)
	var out []TsigGrant
	for i, c := range confs {
		where := fmt.Sprintf("updatepolicy.zone.tsig[%d]", i)
		key := strings.TrimSpace(c.Key)
		switch key {
		case "":
			return nil, fmt.Errorf("%s: no key", where)
		case "*":
			return nil, fmt.Errorf("%s: key \"*\" is not supported; give each key a grant of its own", where)
		}
		g := TsigGrant{Key: canonicalFqdn(key), RRtypes: map[uint16]bool{}}

		g.NameType = strings.ToLower(strings.TrimSpace(c.NameType))
		name := strings.TrimSpace(c.Name)
		switch g.NameType {
		case TsigNameZonesub, TsigNameSelf:
			if name != "" {
				return nil, fmt.Errorf("%s: nametype %s takes no name (got %q)", where, g.NameType, name)
			}
			if g.NameType == TsigNameZonesub {
				g.Name = apex
			} else if !dns.IsSubDomain(apex, g.Key) {
				return nil, fmt.Errorf("%s: nametype self for key %s, which is not a name in zone %s: it could never match", where, g.Key, apex)
			}
		case TsigNameSubdomain, TsigNameName:
			if name == "" {
				return nil, fmt.Errorf("%s: nametype %s needs a name", where, g.NameType)
			}
			g.Name = canonicalFqdn(name)
			if !dns.IsSubDomain(apex, g.Name) {
				return nil, fmt.Errorf("%s: name %s is not in zone %s", where, g.Name, apex)
			}
		case "":
			return nil, fmt.Errorf("%s: no nametype (zonesub, subdomain, name or self)", where)
		default:
			return nil, fmt.Errorf("%s: unknown nametype %q (zonesub, subdomain, name or self)", where, c.NameType)
		}

		if len(c.RRtypes) == 0 {
			return nil, fmt.Errorf("%s: no rrtypes", where)
		}
		for _, t := range c.RRtypes {
			ts := strings.ToUpper(strings.TrimSpace(t))
			if ts == "ANY" {
				g.Any = true
				continue
			}
			rt, ok := dns.StringToType[ts]
			if !ok {
				return nil, fmt.Errorf("%s: unknown rrtype %q", where, t)
			}
			g.RRtypes[rt] = true
		}
		out = append(out, g)
	}
	return out, nil
}
