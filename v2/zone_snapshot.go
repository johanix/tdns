package tdns

import (
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const DefaultPublishCadence = 5 * time.Second

// ZoneSnapshot is the immutable reader-facing view of a zone at one serial
// boundary. Published snapshots are never mutated in place.
type ZoneSnapshot struct {
	Serial          uint32
	SOA             *dns.SOA
	Apex            *OwnerData
	Data            map[string]*OwnerData
	TransportSignal *core.RRset
	IxfrChain       []Ixfr
}

// PendingChanges describes staged-but-unpublished zone deltas (B2 observability).
type PendingChanges struct {
	PublishedSerial uint32
	PublishQueued   bool
	Added           []string
	Replaced        []pendingOwnerChange
	Deleted         []pendingOwnerChange
}

type pendingOwnerChange struct {
	Owner   string
	RRtypes []uint16
}

func parsePublishCadence(s string) (time.Duration, error) {
	if s == "" {
		return DefaultPublishCadence, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < time.Second {
		return 0, errPublishCadenceTooShort
	}
	return d, nil
}

var errPublishCadenceTooShort = &publishCadenceError{"publish-cadence must be at least 1s"}

type publishCadenceError struct{ msg string }

func (e *publishCadenceError) Error() string { return e.msg }

// cloneRRset returns a fresh RRset with copied RRs and RRSIGs. Whole-RRset
// replace and append paths must use this when rs may alias published snapshot
// memory (e.g. built from a GetOwner handle).
func cloneRRset(rs core.RRset) core.RRset {
	out := rs
	if len(rs.RRs) > 0 {
		out.RRs = make([]dns.RR, len(rs.RRs))
		for i, rr := range rs.RRs {
			out.RRs[i] = dns.Copy(rr)
		}
	} else {
		out.RRs = nil
	}
	if len(rs.RRSIGs) > 0 {
		out.RRSIGs = make([]dns.RR, len(rs.RRSIGs))
		for i, rr := range rs.RRSIGs {
			out.RRSIGs[i] = dns.Copy(rr)
		}
	} else {
		out.RRSIGs = nil
	}
	return out
}

func cloneTransportSignal(ts *core.RRset) *core.RRset {
	if ts == nil {
		return nil
	}
	cloned := cloneRRset(*ts)
	return &cloned
}

func snapshotMapFromData(data *core.ConcurrentMap[string, OwnerData]) map[string]*OwnerData {
	if data == nil || data.IsEmpty() {
		return map[string]*OwnerData{}
	}
	out := make(map[string]*OwnerData, data.Count())
	for _, name := range data.Keys() {
		if od, ok := data.Get(name); ok {
			odCopy := od
			out[name] = &odCopy
		}
	}
	return out
}

func apexFromSnapshotData(zd *ZoneData, data map[string]*OwnerData) *OwnerData {
	if zd == nil || data == nil {
		return nil
	}
	return data[zd.ZoneName]
}

func soaFromApex(serial uint32, apex *OwnerData) *dns.SOA {
	if apex == nil {
		return nil
	}
	rs := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(rs.RRs) == 0 {
		return nil
	}
	soa, ok := rs.RRs[0].(*dns.SOA)
	if !ok {
		return nil
	}
	copy := dns.Copy(soa).(*dns.SOA)
	copy.Serial = serial
	return copy
}

func copyIxfrChain(chain []Ixfr) []Ixfr {
	if len(chain) == 0 {
		return nil
	}
	out := make([]Ixfr, len(chain))
	copy(out, chain)
	return out
}

func publishCadenceForZone(zd *ZoneData) time.Duration {
	if zd == nil || zd.publishCadence == 0 {
		return DefaultPublishCadence
	}
	return zd.publishCadence
}
