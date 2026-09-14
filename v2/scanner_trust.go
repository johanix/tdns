/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// What the scanner has to see before it copies a child's data into the
// parent (#637).
//
// The delegation policy bound to the parent zone decides: the same policy that
// decides whether a child's SIG(0) key is trusted (childKeyAcceptable,
// truststore_verify.go). The scanner used to read the global scanner.options
// instead and never the policy, and it never validated CSYNC data at all, so a
// parent whose policy said require-dnssec applied NS changes from
// unauthenticated answers.
//
// require-dnssec: true
//   - CSYNC (RFC 7477 §2, §3): the SOA, the CSYNC and every RRset copied from
//     the child validate Secure, or the CSYNC is not processed.
//   - CDS for a child with a DS (RFC 7344 §6.2): the CDS validates Secure. The
//     §4.1 signer rule, a key in the DS RRset, is #641.
//   - CDS for a child without a DS: a mechanism the policy lists, validated.
//     at-ns is RFC 9615; at-apex needs a CDS that validates at the apex.
//
// require-dnssec: false
//   - the same paths without validation, and the scan response says so.
//
// What is validated is what the child's nameservers served, fetched directly
// with DO set and the RRSIGs kept, and handed to the IMR's validator. Asking the
// IMR for the RRsets instead would validate what it has cached, which right
// after a NOTIFY is typically the data the NOTIFY says has changed.

// ScanValidation says how the child data behind a scan result was
// authenticated. Empty means no decision was reached: the scan stopped before
// there was anything to copy.
type ScanValidation string

const (
	// ScanValidated: every RRset the result rests on validated Secure.
	ScanValidated ScanValidation = "validated"
	// ScanUnvalidated: accepted without validation, because the parent zone's
	// delegation policy does not require DNSSEC.
	ScanUnvalidated ScanValidation = "unvalidated"
	// ScanRefused: not processed, because the policy requires something the
	// child's data did not show.
	ScanRefused ScanValidation = "refused"
)

// scanRefusal is a refusal on trust grounds, as opposed to a failure to reach
// the child. The difference matters in computeCsyncDelta: a nameserver whose
// glue could not be fetched is skipped, but glue that was fetched and did not
// validate stops the whole CSYNC.
type scanRefusal struct{ msg string }

func (e *scanRefusal) Error() string { return e.msg }

func refusef(format string, args ...any) error {
	return &scanRefusal{msg: fmt.Sprintf(format, args...)}
}

func isScanRefusal(err error) bool {
	var r *scanRefusal
	return errors.As(err, &r)
}

// refuseScan marks a response refused and strips anything it would change.
func refuseScan(r *ScanTupleResponse, err error) {
	r.Error = true
	r.ErrorMsg = err.Error()
	r.Validation = ScanRefused
	r.ValidationReason = err.Error()
	r.DataChanged = false
	r.DSAdds, r.DSRemoves = nil, nil
	r.NSAdds, r.NSRemoves = nil, nil
	r.GlueAdds, r.GlueRemoves = nil, nil
}

// scanResponseChangesDelegation reports whether the engine applies a scan
// result. Only one that reached a trust decision, and was not refused, is
// applied; a result that carries changes without saying how its data was
// authenticated is not.
func scanResponseChangesDelegation(resp ScanTupleResponse) bool {
	if resp.Error || !resp.DataChanged {
		return false
	}
	if resp.Validation != ScanValidated && resp.Validation != ScanUnvalidated {
		return false
	}
	return len(resp.DSAdds)+len(resp.DSRemoves)+len(resp.NSAdds)+len(resp.NSRemoves)+
		len(resp.GlueAdds)+len(resp.GlueRemoves) > 0
}

func (p DelegationPolicy) hasMechanism(mech string) bool {
	for _, m := range p.Mechanisms {
		if m == mech {
			return true
		}
	}
	return false
}

// cdsIsRemoval reports whether cds carries the RFC 8078 §4 removal sentinel
// (algorithm 0).
func cdsIsRemoval(cds *core.RRset) bool {
	for _, rr := range cds.RRs {
		if c, ok := rr.(*dns.CDS); ok && c.Algorithm == 0 {
			return true
		}
	}
	return false
}

// askChild asks every nameserver in nsRRset for (qname, qtype) and reports
// whether they agree. The RRset carries the RRSIGs of the first answer.
func (scanner *Scanner) askChild(ctx context.Context, qname string, qtype uint16, nsRRset *core.RRset, lg *log.Logger) (*core.RRset, bool, error) {
	if scanner.queryChild != nil {
		return scanner.queryChild(ctx, qname, qtype, nsRRset)
	}
	return scanner.queryAllNSAndCompare(ctx, qname, qtype, nsRRset, scanner.imr(), lg)
}

// validateChildData runs the IMR's validator over an RRset fetched from the
// child.
func (scanner *Scanner) validateChildData(ctx context.Context, rrset *core.RRset) (cache.ValidationState, error) {
	if scanner.validateRRset != nil {
		return scanner.validateRRset(ctx, rrset)
	}
	imr := scanner.imr()
	if imr == nil || imr.Cache == nil {
		return cache.ValidationStateNone, errors.New("no IMR available to validate with")
	}
	return imr.Cache.ValidateRRsetWithParentZone(ctx, rrset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
}

func validationStateName(s cache.ValidationState) string {
	if name, ok := cache.ValidationStateToString[s]; ok {
		return name
	}
	return "not validated"
}

// requireSecure returns nil when rrset validates Secure, and otherwise a
// refusal that names the policy, the RRset and the verdict.
func (scanner *Scanner) requireSecure(ctx context.Context, rrset *core.RRset, pol DelegationPolicy) error {
	what := fmt.Sprintf("%s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
	state, err := scanner.validateChildData(ctx, rrset)
	if err != nil {
		return refusef("delegation policy %q requires DNSSEC, and %s could not be validated: %v", pol.Name, what, err)
	}
	if state != cache.ValidationStateSecure {
		return refusef("delegation policy %q requires DNSSEC, and %s is %s", pol.Name, what, validationStateName(state))
	}
	return nil
}

// securedChildRRsetFetcher is childRRsetFetcher for a parent whose policy
// requires DNSSEC. An RRset the child's nameservers agree on is handed on only
// if it validates Secure (RFC 7477 §2: the parental agent "MUST perform DNSSEC
// validation of any data to be copied from the child to the parent").
//
// An empty answer has no signature to validate, so it is an error rather than
// data: the NS pass stops on it, and the glue pass leaves that nameserver's
// glue as it is. queryAllNSAndCompare reports an empty RRset the nameservers
// agree on as data; here it stops counting as proof of absence, because the
// denial behind it is not validated.
func (scanner *Scanner) securedChildRRsetFetcher(pol DelegationPolicy, nsRRset *core.RRset, lg *log.Logger) childRRsetFetcher {
	return func(ctx context.Context, name string, qtype uint16) ([]dns.RR, bool, error) {
		rrset, inSync, err := scanner.askChild(ctx, name, qtype, nsRRset, lg)
		if err != nil {
			return nil, false, err
		}
		if rrset == nil || len(rrset.RRs) == 0 {
			return nil, false, fmt.Errorf("no %s %s served, nothing to validate", name, dns.TypeToString[qtype])
		}
		if !inSync {
			// Every caller stops on a disagreement; there is no one RRset to
			// validate.
			return rrset.RRs, false, nil
		}
		if err := scanner.requireSecure(ctx, rrset, pol); err != nil {
			return nil, false, err
		}
		return rrset.RRs, true, nil
	}
}

// authenticateCDS decides whether cds, which every one of the child's
// nameservers serves, may change the child's DS RRset under the parent zone's
// delegation policy. It returns the RRset to act on (the RFC 9615 path uses the
// signaling-name copy), how it was authenticated and why; or a refusal.
func (scanner *Scanner) authenticateCDS(ctx context.Context, childZone string, nsRRset, cds *core.RRset,
	hasDS bool, pol DelegationPolicy, lg *log.Logger) (*core.RRset, ScanValidation, string, error) {

	if hasDS {
		// RFC 7344 §6.2: the parental agent obtains a validated CDS. It
		// validates through the DS the parent already holds.
		if !pol.RequireDnssec {
			return cds, ScanUnvalidated, fmt.Sprintf("delegation policy %q does not require DNSSEC", pol.Name), nil
		}
		if err := scanner.requireSecure(ctx, cds, pol); err != nil {
			return nil, ScanRefused, "", err
		}
		return cds, ScanValidated, "CDS validated through the child's DS", nil
	}

	// No DS: a bootstrap, through a mechanism the policy lists.
	if pol.hasMechanism("at-ns") {
		sigCDS, allValidated, err := scanner.queryCDSAtSignalingNames(ctx, childZone, nsRRset, cds, pol.RequireDnssec, lg)
		if err != nil {
			return nil, ScanRefused, "", refusef("delegation policy %q: RFC 9615 signaling verification failed: %v", pol.Name, err)
		}
		if sigCDS != nil {
			if allValidated {
				return sigCDS, ScanValidated, "CDS validated at the RFC 9615 signaling names", nil
			}
			return sigCDS, ScanUnvalidated, fmt.Sprintf("CDS found at the RFC 9615 signaling names; delegation policy %q does not require DNSSEC", pol.Name), nil
		}
		// Every nameserver is inside the child, so there is no signaling name.
	}
	if pol.hasMechanism("at-apex") {
		if pol.RequireDnssec {
			if err := scanner.requireSecure(ctx, cds, pol); err != nil {
				return nil, ScanRefused, "", err
			}
			return cds, ScanValidated, "CDS validated at the child's apex", nil
		}
		// RFC 8078 §3.3 "Accept after Delay" is monitoring over time. Only a
		// single check exists, so a config asking for more gets nothing rather
		// than less than it asked for.
		if scanner.AtApexChecks > 1 {
			return nil, ScanRefused, "", refusef("scanner.at-apex.checks is %d, but only one check is implemented: an unvalidated at-apex bootstrap is refused", scanner.AtApexChecks)
		}
		return cds, ScanUnvalidated, fmt.Sprintf("RFC 8078 at-apex bootstrap after one check; delegation policy %q does not require DNSSEC", pol.Name), nil
	}
	return nil, ScanRefused, "", refusef("delegation policy %q has no bootstrap mechanism that applies to %s (mechanisms %v)", pol.Name, childZone, pol.Mechanisms)
}

// retiredScannerOptions are the scanner.options tokens that used to decide
// what the scanner trusted, and the policy setting that decides it now.
var retiredScannerOptions = []struct{ option, replacement string }{
	{"no-dnssec-validation", "require-dnssec: false in the delegation policy bound to the parent zone"},
	{"at-apex", "at-apex in the mechanisms of the delegation policy bound to the parent zone"},
	{"at-ns", "at-ns in the mechanisms of the delegation policy bound to the parent zone"},
}

// logTrustConfig reports, at startup, scanner settings that no longer do what
// they say.
func (scanner *Scanner) logTrustConfig() {
	for _, r := range retiredScannerOptions {
		if scanner.HasOption(r.option) {
			lg.Warn("ScannerEngine: scanner.options no longer decides what the scanner trusts; the parent zone's delegation policy does",
				"option", r.option, "instead", r.replacement)
		}
	}
	if scanner.AtApexChecks > 1 {
		lg.Error("ScannerEngine: scanner.at-apex.checks > 1 is not implemented; an unvalidated at-apex CDS bootstrap will be refused",
			"checks", scanner.AtApexChecks)
	}
}

// noteIgnoredOptions says, at the point it matters, that no-dnssec-validation
// has no effect under a policy that requires DNSSEC.
func (scanner *Scanner) noteIgnoredOptions(pol DelegationPolicy, parent, child string) {
	if pol.RequireDnssec && scanner.HasOption("no-dnssec-validation") {
		lg.Warn("ScannerEngine: scanner.options no-dnssec-validation is ignored: the parent zone's delegation policy requires DNSSEC",
			"parent", parent, "child", child, "policy", pol.Name)
	}
}
