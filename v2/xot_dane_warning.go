/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Loud warnings for DANE while DNSSEC validation is not enforced.
 */
package tdns

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// DANE checks a certificate against the TLSA record at _<port>._tcp.<name>.
// That proves something only when the TLSA record is DNSSEC-validated. With
// imrengine.require-dnssec-validation: false the resolver takes a TLSA record
// it could not validate, and then anyone on the path can forge both the TLSA
// record and the certificate. tdns still accepts it (the lab-mode escape
// hatch), but says so wherever the operator looks: in the response to a zone
// add or modify through the API, in the log at config load, in `zone desc`
// for each lookup that took an unvalidated TLSA, and in daemon status.

// daneNotValidated is the text every such warning carries.
const daneNotValidated = "DANE without DNSSEC validation (imrengine.require-dnssec-validation: false): the TLSA record is not validated, so the certificate check proves nothing"

// TLSANotValidatedWarning is what `zone desc` shows for a primary when the
// serial probe took its TLSA record without DNSSEC validation.
const TLSANotValidatedWarning = "TLSA not DNSSEC-validated (imrengine.require-dnssec-validation: false): the certificate check proves nothing"

// daneWarningZonesShown caps how many zones daemon status names.
const daneWarningZonesShown = 10

// peerUsesDANE reports whether p is an XoT primary authenticated by DANE.
// Case-insensitive, like peerUsesDoT, so it holds before normalization too.
func peerUsesDANE(p PeerConf) bool {
	return peerUsesDoT(p) && strings.EqualFold(strings.TrimSpace(p.TLSAuth), TLSAuthDANE)
}

// daneThroughAny is the text for a downstreams entry with a dane tls-identity
// under a downstream-auth that lists "any": the ladder then accepts it on its
// address and TSIG alone, before any TLS check (authorizeTransfer).
const daneThroughAny = "DANE downstream reached through downstream-auth any: any accepts it without checking its certificate, and with imrengine.require-dnssec-validation: false the TLSA record would not be validated either"

// daneDownstreams returns the non-BLOCKED downstreams entries that carry a
// dane tls-identity with a name, when the zone's downstream-auth lists
// tls-dane or "any". Each is named by its TLS name, plus its peer name if it
// has one. viaAny is true when the list holds "any", which skips every TLS
// check: those peers are then reached through any, not through tls-dane.
func daneDownstreams(mechs []string, downstreams []AclEntry) (names []string, viaAny bool) {
	dane := false
	for _, m := range mechs {
		switch strings.ToLower(strings.TrimSpace(m)) {
		case MechAny:
			viaAny = true
		case MechTLSDane:
			dane = true
		}
	}
	if !dane && !viaAny {
		return nil, false
	}
	var out []string
	for _, e := range downstreams {
		ti := e.TLSIdentity
		if e.Key == BLOCKED || ti == nil || !ti.Dane || ti.Name == "" {
			continue
		}
		name := ti.Name
		if e.PeerName != "" {
			name = fmt.Sprintf("%s (peer %s)", ti.Name, e.PeerName)
		}
		out = append(out, name)
	}
	return out, viaAny
}

// danePrimaryWarnings logs, at WARN, each primary of zone that uses tls-auth:
// dane while this daemon does not enforce DNSSEC validation, and returns the
// same warnings as text for an API response. nil when validation is enforced.
func (conf *Config) danePrimaryWarnings(logger *slog.Logger, zone string, primaries []PeerConf) []string {
	if !conf.DnssecValidationNotEnforced() {
		return nil
	}
	var out []string
	for _, p := range primaries {
		if !peerUsesDANE(p) {
			continue
		}
		logger.Warn(daneNotValidated, "zone", zone, "primary", p.Addr)
		out = append(out, fmt.Sprintf("zone %s: primary %s: %s", zone, p.Addr, daneNotValidated))
	}
	return out
}

// daneDownstreamWarnings is danePrimaryWarnings for the downstreams entries
// with a dane tls-identity. The lookup that checks a client certificate shares
// the same escape hatch (verifyClientCertDANE). Under "any" the text says the
// peer is reached through any instead.
func (conf *Config) daneDownstreamWarnings(logger *slog.Logger, zone string, mechs []string, downstreams []AclEntry) []string {
	if !conf.DnssecValidationNotEnforced() {
		return nil
	}
	names, viaAny := daneDownstreams(mechs, downstreams)
	msg := daneNotValidated
	if viaAny {
		msg = daneThroughAny
	}
	var out []string
	for _, name := range names {
		logger.Warn(msg, "zone", zone, "downstream", name)
		out = append(out, fmt.Sprintf("zone %s: downstream %s: %s", zone, name, msg))
	}
	return out
}

// zoneDaneWarnings is the warnings for a zone as it now stands in Zones: its
// primaries and its downstreams entries. The API add and modify responses
// carry it. A modify that keeps the old primaries still gets the warning,
// because the zone still uses them.
func (conf *Config) zoneDaneWarnings(logger *slog.Logger, zone string) []string {
	if !conf.DnssecValidationNotEnforced() {
		return nil
	}
	zone = dns.Fqdn(zone)
	zd, ok := Zones.Get(zone)
	if !ok || zd == nil {
		return nil
	}
	primaries, mechs, downstreams := zd.daneSnapshot()
	warnings := conf.danePrimaryWarnings(logger, zone, primaries)
	return append(warnings, conf.daneDownstreamWarnings(logger, zone, mechs, downstreams)...)
}

// daneSnapshot copies, under zd.mu, what the DANE checks read.
func (zd *ZoneData) daneSnapshot() ([]PeerConf, []string, []AclEntry) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return clonePeerConfs(zd.PrimariesConf),
		append([]string(nil), zd.DownstreamAuth...),
		append([]AclEntry(nil), zd.Downstreams...)
}

// zoneUsesDANE reports whether a primary or a downstreams entry of zd is
// authenticated by DANE.
func (zd *ZoneData) zoneUsesDANE() bool {
	primaries, mechs, downstreams := zd.daneSnapshot()
	for _, p := range primaries {
		if peerUsesDANE(p) {
			return true
		}
	}
	names, _ := daneDownstreams(mechs, downstreams)
	return len(names) > 0
}

// daneZonesWarning names, for daemon status, the zones that use DANE while
// DNSSEC validation is not enforced. Empty when validation is enforced or no
// zone uses DANE. At most daneWarningZonesShown zones are named.
func (conf *Config) daneZonesWarning() string {
	if !conf.DnssecValidationNotEnforced() {
		return ""
	}
	var zones []string
	for item := range Zones.IterBuffered() {
		if item.Val != nil && item.Val.zoneUsesDANE() {
			zones = append(zones, item.Key)
		}
	}
	if len(zones) == 0 {
		return ""
	}
	sort.Strings(zones)
	shown := zones
	more := ""
	if len(zones) > daneWarningZonesShown {
		shown = zones[:daneWarningZonesShown]
		more = fmt.Sprintf(" and %d more", len(zones)-daneWarningZonesShown)
	}
	return fmt.Sprintf("DANE without DNSSEC validation in %d zone(s): %s%s: the TLSA records are not validated, so the certificate checks prove nothing",
		len(zones), strings.Join(shown, ", "), more)
}
