/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Why a presented client certificate did not authenticate.
//
// These are log values, not response text: the 401 stays undifferentiated (see
// dsyncApiCertAuthFailure). Short and stable so they can be grepped and
// alerted on; the detail that makes one actionable travels alongside in the
// per-identity notes.
const (
	dsyncApiCertNoCertificate   = "no-client-certificate"
	dsyncApiCertNoIdentity      = "no-usable-identity"
	dsyncApiCertUnknownIdentity = "unknown-identity"
	dsyncApiCertDisabled        = "credential-disabled"
	dsyncApiCertExpired         = "credential-expired"
	dsyncApiCertUntrustedChain  = "untrusted-chain"
	dsyncApiCertStoreError      = "credential-store-error"
)

// dsyncApiCertReasonRank orders the reasons by how much they tell an operator,
// because one request can produce several: a certificate with three SANs, two
// unregistered and one registered but not chaining to the ca-file, has one
// answer worth reporting and two that only say "not this one".
//
// Ranked rather than first-wins so the reported reason does not depend on the
// order the SANs happen to appear in the certificate.
var dsyncApiCertReasonRank = map[string]int{
	dsyncApiCertNoCertificate:   1,
	dsyncApiCertNoIdentity:      2,
	dsyncApiCertUnknownIdentity: 3,
	dsyncApiCertDisabled:        4,
	dsyncApiCertExpired:         5,
	dsyncApiCertUntrustedChain:  6,
	dsyncApiCertStoreError:      7,
}

// dsyncApiCertAuthNote is one identity's outcome: what was looked up under
// which mechanism, and what happened.
type dsyncApiCertAuthNote struct {
	Mech     string
	Identity string
	Reason   string
	Err      error
}

func (n dsyncApiCertAuthNote) String() string {
	s := fmt.Sprintf("%s %s: %s", n.Mech, n.Identity, n.Reason)
	if n.Err != nil {
		s += fmt.Sprintf(" (%v)", n.Err)
	}
	return s
}

// refusal reports whether this note is a credential being turned away rather
// than simply not found. With several mechanisms configured most requests miss
// most of them, which is routine and not worth a word.
func (n dsyncApiCertAuthNote) refusal() bool {
	switch n.Reason {
	case dsyncApiCertDisabled, dsyncApiCertExpired, dsyncApiCertUntrustedChain:
		return true
	}
	return false
}

// dsyncApiCertAuthFailure is why a presented client certificate did not
// authenticate. It exists to be logged.
//
// The response stays an undifferentiated 401 on purpose: telling an
// unauthenticated caller which identities are registered, or that the one it
// presented exists but is disabled, is exactly what the Basic path avoids by
// logging the username and answering without one. So the server log is the
// only place the answer can appear, and before issue #533 it did not appear
// there either -- the line carried the zone, the child and the remote address,
// while the matching success line named the resolved principal. Success said
// who you turned out to be; failure did not say who you claimed to be.
type dsyncApiCertAuthFailure struct {
	// Reason is the most specific outcome seen, by dsyncApiCertReasonRank.
	Reason string
	// Err is the error behind Reason, where there is one: the chain
	// verification failure, or the store error.
	Err error
	// Notes is every identity considered, in the order tried.
	Notes []dsyncApiCertAuthNote

	// The certificate as presented. Subject and issuer are what an operator
	// compares against the certificate on the client; serial is what names
	// this certificate exactly; notafter answers "has it expired" without a
	// round trip to the client's filesystem.
	Subject  string
	Issuer   string
	Serial   string
	NotAfter string
}

// note records one identity's outcome, promoting Reason when this outcome says
// more than what is already recorded.
func (f *dsyncApiCertAuthFailure) note(mech, identity, reason string, err error) {
	f.Notes = append(f.Notes, dsyncApiCertAuthNote{Mech: mech, Identity: identity, Reason: reason, Err: err})
	if dsyncApiCertReasonRank[reason] > dsyncApiCertReasonRank[f.Reason] {
		f.Reason = reason
		f.Err = err
	}
}

// LogArgs renders the failure as slog key/value pairs, to be appended to the
// caller's own zone/child/from.
func (f *dsyncApiCertAuthFailure) LogArgs() []any {
	args := []any{"reason", f.Reason}
	for _, kv := range [][2]string{
		{"subject", f.Subject}, {"issuer", f.Issuer},
		{"serial", f.Serial}, {"notafter", f.NotAfter},
	} {
		if kv[1] != "" {
			args = append(args, kv[0], kv[1])
		}
	}
	// The notes carry the underlying error already -- whatever set Reason set
	// Err, and that note is in the list -- so Err is deliberately not repeated
	// as its own key. These lines are long enough.
	if s := joinDsyncApiCertNotes(f.Notes, false); s != "" {
		args = append(args, "considered", s)
	}
	return args
}

// storeError reports whether the walk hit the credential store itself rather
// than a verdict about a credential. It stops the walk: a store that cannot be
// read has not said the credential is absent, and trying the next mechanism
// against the same broken store answers nothing.
func (f *dsyncApiCertAuthFailure) storeError() bool {
	return f.Reason == dsyncApiCertStoreError
}

func joinDsyncApiCertNotes(notes []dsyncApiCertAuthNote, refusalsOnly bool) string {
	var out []string
	for _, n := range notes {
		if refusalsOnly && !n.refusal() {
			continue
		}
		out = append(out, n.String())
	}
	return strings.Join(out, "; ")
}

// authenticateDsyncApiClientCert resolves a presented client certificate to a
// DsyncApiCredential using the identity walk in the implementation plan (D2).
//
// Failure is undifferentiated to the caller -- unknown identity, disabled,
// expired and a chain that does not verify all yield a 401 with no body -- but
// no longer undifferentiated in the log: the returned failure carries the
// identity that was presented and the reason it was refused.
func authenticateDsyncApiClientCert(kdb *KeyDB, zone string, r *http.Request,
	ca *DsyncApiClientAuthConf) (*DsyncApiCredential, *dsyncApiCertAuthFailure) {

	if ca == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, &dsyncApiCertAuthFailure{Reason: dsyncApiCertNoCertificate}
	}
	leaf := r.TLS.PeerCertificates[0]
	presented := r.TLS.PeerCertificates[1:]

	fail := &dsyncApiCertAuthFailure{
		Subject:  leaf.Subject.String(),
		Issuer:   leaf.Issuer.String(),
		Serial:   fmt.Sprintf("%x", leaf.SerialNumber),
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
	}

	for _, mech := range ca.Mechanisms {
		cred := authenticateDsyncApiClientCertMech(kdb, zone, mech, leaf, presented, ca.CAFile, fail)
		if fail.storeError() {
			return nil, fail
		}
		if cred != nil {
			// Authenticated -- but a credential turned away on the road to
			// this one is worth a line even though the request succeeds. A
			// disabled pin stepped over in silence is how an operator comes to
			// believe a revocation took effect when another row still lets the
			// same certificate in.
			if s := joinDsyncApiCertNotes(fail.Notes, true); s != "" {
				lgDsyncApi.Warn("DSYNC API certificate credentials refused before one was accepted",
					"zone", zone, "principal", cred.Principal, "auth", cred.AuthMethod, "refused", s)
			}
			return cred, nil
		}
	}
	return nil, fail
}

// authenticateDsyncApiClientCertMech tries one mechanism, appending a note for
// every identity it considered. A nil credential means "not this one, try the
// next"; a store error is reported through fail and stops the walk.
func authenticateDsyncApiClientCertMech(kdb *KeyDB, zone, mech string, leaf *x509.Certificate,
	presented []*x509.Certificate, caFile string, fail *dsyncApiCertAuthFailure) *DsyncApiCredential {

	switch mech {
	case DsyncApiAuthTLSPin:
		pin := SPKISHA256(leaf)
		row, err := kdb.LookupDsyncApiCertCredential(zone, mech, pin)
		if err != nil {
			fail.note(mech, pin, dsyncApiCertStoreError, err)
			return nil
		}
		if row == nil {
			fail.note(mech, pin, dsyncApiCertUnknownIdentity, nil)
			return nil
		}
		if reason := dsyncApiCertUnusable(row); reason != "" {
			// Not a hit: try the next mechanism. A disabled pin must not
			// lock out a live pkix row for the same certificate.
			fail.note(mech, row.Identity, reason, nil)
			return nil
		}
		cred := row.asDsyncApiCredential()
		return &cred

	case DsyncApiAuthTLSPkix:
		if len(leaf.DNSNames) == 0 {
			// The walk is over dNSName SANs only -- the CN is deliberately not
			// consulted -- so a certificate without one has nothing to look up.
			fail.note(mech, "(no dNSName SAN)", dsyncApiCertNoIdentity, nil)
			return nil
		}
		for _, name := range leaf.DNSNames {
			identity := core.CanonicalizeName(dns.Fqdn(name))
			row, err := kdb.LookupDsyncApiCertCredential(zone, mech, identity)
			if err != nil {
				fail.note(mech, identity, dsyncApiCertStoreError, err)
				return nil
			}
			if row == nil {
				fail.note(mech, identity, dsyncApiCertUnknownIdentity, nil)
				continue
			}
			if err := verifyClientCertPKIX(leaf, presented, caFile, identity); err != nil {
				fail.note(mech, identity, dsyncApiCertUntrustedChain, err)
				continue
			}
			if reason := dsyncApiCertUnusable(row); reason != "" {
				fail.note(mech, row.Identity, reason, nil)
				continue
			}
			cred := row.asDsyncApiCredential()
			return &cred
		}
		return nil

	default:
		// Unknown names are a config error and are refused at load.
		return nil
	}
}

// dsyncApiCertUnusable names why a stored credential cannot be used, or "" if
// it can.
//
// Usable stays the single gate, so the decision cannot drift from the reason;
// the reason is derived only for the log. Disabled is reported ahead of
// expired when a row is both, because disabling is the deliberate act and is
// what has to be undone either way.
func dsyncApiCertUnusable(row *DsyncApiCertCredential) string {
	now := time.Now()
	if row.Usable(now) {
		return ""
	}
	if row.Disabled {
		return dsyncApiCertDisabled
	}
	return dsyncApiCertExpired
}
