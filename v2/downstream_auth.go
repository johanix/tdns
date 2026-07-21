/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Per-zone transfer authentication — the downstream-auth mechanism ladder
 * (docs/2026-07-21-peers-xfr-auth-design.md §5/§6). Policy lives on the
 * zone (zd.DownstreamAuth: which proof classes are acceptable), credentials
 * live on the matched downstreams entries (prefix/key inline; tls-identity
 * via peers references). Enforcement happens at TRANSFER time, never at the
 * TLS handshake: the DoT listener merely REQUESTS a client certificate
 * (tls.RequestClientCert) and verifies nothing, so cert-less DoT query
 * clients and every non-TLS transport are unaffected.
 */
package tdns

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// Transfer-auth mechanism classes, weakest to strongest. Each tls-* class
// escalates ON TOP of the matched entry's address/TSIG requirements — it
// never replaces them.
const (
	MechPrefix  = "prefix"   // address match alone (entry key was NOKEY)
	MechTsig    = "tsig"     // address match + valid TSIG
	MechTLSPin  = "tls-pin"  // + client cert SPKI in the entry's pins
	MechTLSPkix = "tls-pkix" // + client cert chains to the entry's CA (+ SAN name)
	MechTLSDane = "tls-dane" // + client cert matches the name's validated TLSA
	MechAny     = "any"      // sentinel: unrestricted (template override)
)

var validMechanisms = map[string]bool{
	MechPrefix: true, MechTsig: true, MechTLSPin: true,
	MechTLSPkix: true, MechTLSDane: true, MechAny: true,
}

// daneClientTLSAPort is the port used to form the TLSA owner
// (_853._tcp.<name>) when verifying a DOWNSTREAM's client certificate via
// tls-dane: the secondary publishes the TLSA record for its own DoT service
// port, which is what tdns-cli cert init emits.
const daneClientTLSAPort = "853"

// authorizeTransfer is the complete inbound AXFR/IXFR authorization gate:
// the downstreams ACL (address + TSIG, semantics unchanged from matchACL /
// checkInboundTSIG) plus the per-zone downstream-auth mechanism ladder.
// Returns nil when the transfer is authorized. imr may be nil; it is only
// needed for the tls-dane mechanism (which fails closed without it).
func (zd *ZoneData) authorizeTransfer(w dns.ResponseWriter, r *dns.Msg, imr *Imr) error {
	src, ok := peerIP(w.RemoteAddr().String())
	if !ok {
		return fmt.Errorf("unparseable source %q", w.RemoteAddr())
	}

	// BLOCKED supersedes any allow entry, wherever it appears.
	for _, e := range zd.Downstreams {
		if e.Key == BLOCKED && ipSpecMatch(e.Prefix, src) {
			return fmt.Errorf("source %s is BLOCKED by the downstreams ACL", src)
		}
	}

	// Collect the matched entries: prefix match + the entry's TSIG
	// requirement satisfied (NOKEY = unsigned accepted; a named key needs a
	// verified TSIG with that name — the dual-key overlap accepts any
	// matching entry).
	matched := matchedDownstreams(zd.Downstreams, src, w, r)
	if len(matched) == 0 {
		return fmt.Errorf("source %s not permitted by the downstreams ACL (no entry matched address+TSIG)", src)
	}

	allowed := zd.DownstreamAuth
	if len(allowed) == 0 {
		return nil // no ladder configured: any matched entry authorizes (pre-ladder behavior)
	}
	allowedSet := map[string]bool{}
	for _, m := range allowed {
		if m == MechAny {
			return nil // explicit "unrestricted" (template override)
		}
		allowedSet[m] = true
	}

	// The TLS mechanisms need the connection's client certificate (which the
	// listener requested but did NOT verify — verification happens here,
	// per matched entry).
	cs := connectionState(w)
	var leaf *x509.Certificate
	var presented []*x509.Certificate
	if cs != nil && len(cs.PeerCertificates) > 0 {
		leaf = cs.PeerCertificates[0]
		presented = cs.PeerCertificates[1:]
	}

	var tried []string
	for _, e := range matched {
		base := MechTsig
		if e.Key == NOKEY || e.Key == "" {
			base = MechPrefix
		}
		if allowedSet[base] {
			return nil
		}
		tried = append(tried, base)

		ti := e.TLSIdentity
		if ti == nil || leaf == nil {
			continue
		}
		if allowedSet[MechTLSPin] && len(ti.Pins) > 0 {
			if pinMatches(leaf, ti.Pins) {
				return nil
			}
			tried = append(tried, "tls-pin(no match)")
		}
		if allowedSet[MechTLSPkix] && ti.CAFile != "" {
			if err := verifyClientCertPKIX(leaf, presented, ti.CAFile, ti.Name); err == nil {
				return nil
			} else {
				tried = append(tried, fmt.Sprintf("tls-pkix(%v)", err))
			}
		}
		if allowedSet[MechTLSDane] && ti.Dane && ti.Name != "" {
			if err := verifyClientCertDANE(leaf, ti.Name, imr); err == nil {
				return nil
			} else {
				tried = append(tried, fmt.Sprintf("tls-dane(%v)", err))
			}
		}
	}
	return fmt.Errorf("no matched downstreams entry satisfies downstream-auth %v (evaluated: %v; client cert present: %v)",
		allowed, tried, leaf != nil)
}

// matchedDownstreams returns every non-BLOCKED entry whose prefix matches
// src AND whose TSIG requirement the request satisfies.
func matchedDownstreams(acl []AclEntry, src netip.Addr, w dns.ResponseWriter, r *dns.Msg) []AclEntry {
	ts := r.IsTsig()
	tsigOK := ts != nil && w.TsigStatus() == nil
	var out []AclEntry
	for _, e := range acl {
		if e.Key == BLOCKED || !ipSpecMatch(e.Prefix, src) {
			continue
		}
		if e.Key == NOKEY || e.Key == "" {
			out = append(out, e)
			continue
		}
		if tsigOK && dns.CanonicalName(ts.Hdr.Name) == dns.CanonicalName(e.Key) {
			out = append(out, e)
		}
	}
	return out
}

// connectionState extracts the TLS state via the miekg ConnectionStater
// interface (implemented by the fork's response writer for tcp-tls
// listeners). Response-writer WRAPPERS (tsigSignResponseWriter in
// production, recording writers in tests) hide the method — embedding the
// dns.ResponseWriter interface only promotes its own methods — so wrappers
// implement Unwrap() and this walks the chain. nil on non-TLS transports.
func connectionState(w dns.ResponseWriter) *tls.ConnectionState {
	for w != nil {
		if cs, ok := w.(interface{ ConnectionState() *tls.ConnectionState }); ok {
			return cs.ConnectionState()
		}
		u, ok := w.(interface{ Unwrap() dns.ResponseWriter })
		if !ok {
			return nil
		}
		w = u.Unwrap()
	}
	return nil
}

// pinMatches reports whether the leaf's SPKI SHA-256 matches any pin
// (constant-time per comparison).
func pinMatches(leaf *x509.Certificate, pins []string) bool {
	got := SPKISHA256(leaf)
	for _, want := range pins {
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// verifyClientCertPKIX chain-verifies the presented client certificate
// against the entry's trust anchors (roots only; intermediates come from
// the client's presented chain) and, when a name is known, requires the
// leaf to carry it as a DNS SAN — chain membership alone is not an
// identity. The listener used RequestClientCert, so nothing was verified
// during the handshake; this is the verification.
func verifyClientCertPKIX(leaf *x509.Certificate, presented []*x509.Certificate, caFile, name string) error {
	data, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("reading ca-file: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return fmt.Errorf("no usable certificates in ca-file %s", caFile)
	}
	inters := x509.NewCertPool()
	for _, c := range presented {
		inters.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("chain: %v", err)
	}
	if name != "" {
		if err := leaf.VerifyHostname(name); err != nil {
			return fmt.Errorf("identity: %v", err)
		}
	}
	return nil
}

// verifyClientCertDANE matches the presented client certificate against the
// DNSSEC-validated TLSA RRset at _853._tcp.<name>. Fails closed: no IMR,
// lookup failure, or a not-secure state all refuse (the lab-mode
// require_dnssec_validation escape hatch is honored inside the lookup).
func verifyClientCertDANE(leaf *x509.Certificate, name string, imr *Imr) error {
	if imr == nil {
		return fmt.Errorf("tls-dane requires the built-in IMR")
	}
	rrset, err := lookupTLSAValidatedIMR(imr, name, daneClientTLSAPort)
	if err != nil {
		return err
	}
	for _, rr := range rrset.RRs {
		if tlsa, ok := rr.(*dns.TLSA); ok {
			if err := VerifyCertAgainstTlsaRR(tlsa, leaf); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("no TLSA record at _%s._tcp.%s matches the client certificate", daneClientTLSAPort, dns.Fqdn(name))
}

// validateDownstreamAuth normalizes (lowercase, in place) and validates a
// zone's downstream-auth list. Returns an error for unknown mechanism names
// (quarantines the zone).
func validateDownstreamAuth(mechs []string) error {
	for i, m := range mechs {
		m = strings.ToLower(strings.TrimSpace(m))
		mechs[i] = m
		if !validMechanisms[m] {
			return fmt.Errorf("unknown downstream-auth mechanism %q (supported: prefix, tsig, tls-pin, tls-pkix, tls-dane, any)", m)
		}
	}
	return nil
}

// mechanismsProducible returns the set of mechanisms one ACL entry can ever
// yield, given its key and (for peer-expanded downstreams entries) its
// tls-identity credentials.
func mechanismsProducible(e AclEntry) []string {
	var can []string
	if e.Key == NOKEY || e.Key == "" {
		can = append(can, MechPrefix)
	} else {
		can = append(can, MechTsig)
	}
	if ti := e.TLSIdentity; ti != nil {
		if len(ti.Pins) > 0 {
			can = append(can, MechTLSPin)
		}
		if ti.CAFile != "" {
			can = append(can, MechTLSPkix)
		}
		if ti.Dane && ti.Name != "" {
			can = append(can, MechTLSDane)
		}
	}
	return can
}

// crossCheckDownstreamAuth emits load-time warnings (never errors) for
// configurations that cannot work as written: a listed mechanism no entry
// can ever satisfy, an entry that can only produce disallowed mechanisms
// (dead entry), and tls-dane without an IMR.
func crossCheckDownstreamAuth(zname string, mechs []string, acl []AclEntry, haveIMR bool) {
	if len(mechs) == 0 {
		return
	}
	allowed := map[string]bool{}
	for _, m := range mechs {
		allowed[m] = true
	}
	if allowed[MechAny] {
		return
	}
	producible := map[string]bool{}
	for _, e := range acl {
		if e.Key == BLOCKED {
			continue
		}
		for _, m := range mechanismsProducible(e) {
			producible[m] = true
		}
	}
	for m := range allowed {
		if !producible[m] {
			lgConfig.Warn("downstream-auth mechanism is allowed but no downstreams entry can satisfy it", "zone", zname, "mechanism", m)
		}
	}
	if allowed[MechTLSDane] && !haveIMR {
		lgConfig.Warn("downstream-auth lists tls-dane but the IMR is not active — the mechanism will be unsatisfiable (fail closed)", "zone", zname)
	}
	for _, e := range acl {
		if e.Key == BLOCKED {
			continue
		}
		can := mechanismsProducible(e)
		dead := true
		for _, m := range can {
			if allowed[m] {
				dead = false
				break
			}
		}
		if dead {
			lgConfig.Warn("downstreams entry can never satisfy this zone's downstream-auth (dead entry)", "zone", zname, "prefix", e.Prefix, "key", e.Key, "peer", e.PeerName, "produces", can, "allowed", mechs)
		}
	}
}
