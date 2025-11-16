package core

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// CacheContext: where an RRset came from
type CacheContext uint8

const (
	ContextAnswer CacheContext = iota + 1
	ContextHint
	ContextPriming
	ContextReferral
	ContextNXDOMAIN
	ContextNoErrNoAns
	ContextGlue
	ContextFailure
)

var CacheContextToString = map[CacheContext]string{
	ContextAnswer:     "answer",
	ContextHint:       "hint",
	ContextPriming:    "priming",
	ContextReferral:   "referral",
	ContextNXDOMAIN:   "NXDOMAIN",
	ContextNoErrNoAns: "NOERROR, NODATA (negative response type 0)",
	ContextGlue:       "glue",
	ContextFailure:    "failure",
}

// Transport and helpers
type Transport uint8

const (
	TransportDo53 Transport = iota + 1
	TransportDoT
	TransportDoH
	TransportDoQ
)

var TransportToString = map[Transport]string{
	TransportDo53: "do53",
	TransportDoT:  "dot",
	TransportDoH:  "doh",
	TransportDoQ:  "doq",
}

var stringToTransport = map[string]Transport{
	"do53": TransportDo53,
	"dot":  TransportDoT,
	"doh":  TransportDoH,
	"doq":  TransportDoQ,
}

func StringToTransport(s string) (Transport, error) {
	if t, ok := stringToTransport[s]; ok {
		return t, nil
	}
	return 0, fmt.Errorf("unknown transport: %q", s)
}

// DNSSEC validity window (RFC 1982 serial arithmetic), mirrored from miekg/dns
const year68 = 1 << 31

func WithinValidityPeriod(inc, exp uint32, t time.Time) bool {
	var utc int64
	if t.IsZero() {
		utc = time.Now().UTC().Unix()
	} else {
		utc = t.UTC().Unix()
	}
	modi := (int64(inc) - utc) / year68
	mode := (int64(exp) - utc) / year68
	ti := int64(inc) + modi*year68
	te := int64(exp) + mode*year68
	return ti <= utc && utc <= te
}

// RRset: on-wire RRset + signatures
type RRset struct {
	Name   string
	Class  uint16
	RRtype uint16
	RRs    []dns.RR
	RRSIGs []dns.RR
}

// Methods on RRset
// RemoveRR removes an RR (and clears RRSIGs) if found.
func (rrset *RRset) RemoveRR(rr dns.RR) {
	if rrset == nil || rr == nil {
		return
	}
	for i, r := range rrset.RRs {
		if dns.IsDuplicate(r, rr) {
			rrset.RRs = append(rrset.RRs[:i], rrset.RRs[i+1:]...)
			rrset.RRSIGs = []dns.RR{}
			return
		}
	}
}

// Copy returns a shallow copy of the RRset (RR slices copied).
func (rrset *RRset) Copy() *RRset {
	if rrset == nil {
		return nil
	}
	newRRset := RRset{
		Name:   rrset.Name,
		Class:  rrset.Class,
		RRtype: rrset.RRtype,
		RRs:    []dns.RR{},
		RRSIGs: []dns.RR{},
	}
	newRRset.RRs = append(newRRset.RRs, rrset.RRs...)
	newRRset.RRSIGs = append(newRRset.RRSIGs, rrset.RRSIGs...)
	return &newRRset
}

// Add adds an RR if not already present.
func (rrset *RRset) Add(rr dns.RR) {
	if rrset == nil || rr == nil {
		return
	}
	for _, rr2 := range rrset.RRs {
		if dns.IsDuplicate(rr, rr2) {
			return
		}
	}
	rrset.RRs = append(rrset.RRs, rr)
}

// Delete deletes a matching RR if present.
func (rrset *RRset) Delete(rr dns.RR) {
	if rrset == nil || rr == nil {
		return
	}
	for i, rr2 := range rrset.RRs {
		if dns.IsDuplicate(rr, rr2) {
			rrset.RRs = append(rrset.RRs[:i], rrset.RRs[i+1:]...)
			return
		}
	}
}


