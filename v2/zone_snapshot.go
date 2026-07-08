package tdns

import (
	"fmt"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const DefaultPublishCadence = 5 * time.Second

// zoneSnapshot is the immutable reader-facing view of a zone at one serial
// boundary. Published snapshots are never mutated in place. The type is
// unexported so callers cannot mutate served data without going through publish.
type zoneSnapshot struct {
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

// PendingChangesView is the JSON/API representation of pendingChanges().
type PendingChangesView struct {
	PublishedSerial uint32                   `json:"published_serial"`
	PublishQueued   bool                     `json:"publish_queued"`
	Added           []string                 `json:"added,omitempty"`
	Replaced        []PendingOwnerChangeJSON `json:"replaced,omitempty"`
	Deleted         []PendingOwnerChangeJSON `json:"deleted,omitempty"`
}

func pendingChangesView(pc *PendingChanges) *PendingChangesView {
	if pc == nil {
		return nil
	}
	v := &PendingChangesView{
		PublishedSerial: pc.PublishedSerial,
		PublishQueued:   pc.PublishQueued,
		Added:           append([]string(nil), pc.Added...),
	}
	for _, ch := range pc.Replaced {
		v.Replaced = append(v.Replaced, pendingOwnerChangeJSON(ch))
	}
	for _, ch := range pc.Deleted {
		v.Deleted = append(v.Deleted, pendingOwnerChangeJSON(ch))
	}
	return v
}

func pendingOwnerChangeJSON(ch pendingOwnerChange) PendingOwnerChangeJSON {
	out := PendingOwnerChangeJSON{
		Owner:   ch.Owner,
		RRtypes: append([]uint16(nil), ch.RRtypes...),
	}
	for _, t := range ch.RRtypes {
		out.TypeNames = append(out.TypeNames, dns.TypeToString[t])
	}
	return out
}

// FormatPendingChanges returns a human-readable summary for CLI output.
func FormatPendingChanges(pc *PendingChanges) string {
	if pc == nil {
		return "no pending changes"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "published serial: %d\n", pc.PublishedSerial)
	fmt.Fprintf(&b, "publish queued: %v\n", pc.PublishQueued)
	for _, name := range pc.Added {
		fmt.Fprintf(&b, "added owner: %s\n", name)
	}
	for _, ch := range pc.Replaced {
		fmt.Fprintf(&b, "replaced owner: %s types: %s\n", ch.Owner, rrtypesString(ch.RRtypes))
	}
	for _, ch := range pc.Deleted {
		fmt.Fprintf(&b, "deleted owner: %s types: %s\n", ch.Owner, rrtypesString(ch.RRtypes))
	}
	return strings.TrimRight(b.String(), "\n")
}

func rrtypesString(types []uint16) string {
	if len(types) == 0 {
		return "-"
	}
	names := make([]string, len(types))
	for i, t := range types {
		names[i] = dns.TypeToString[t]
	}
	return strings.Join(names, ",")
}

type pendingOwnerChange struct {
	Owner   string
	RRtypes []uint16
}

// PendingOwnerChangeJSON is the API/CLI view of a pending owner delta.
type PendingOwnerChangeJSON struct {
	Owner     string   `json:"owner"`
	RRtypes   []uint16 `json:"rrtypes"`
	TypeNames []string `json:"type_names,omitempty"`
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

// snapshotMapFromData builds the snapshot's owner map from a source store.
//
// IMMUTABILITY INVARIANT (copy-strategy-A, per the snapshot-correctness design):
// each entry is a FRESH *OwnerData, but its RRtypes (*RRTypeStore) pointer is
// SHARED with the source by design — deliberately, so large PQ signature bytes
// are not re-copied on every publish. The immutability guarantee therefore rests
// on the source store being FROZEN once snapshotted: callers must never mutate
// `data` (zd.Data, or a discarded new_zd.Data) in place afterwards. Post-B3 all
// writers stage into a fresh workingSet and publish; the CI grep gate forbids
// direct RRtypes.Set/Data.Set on the live path. A future direct writer to a
// snapshotted store would silently reintroduce the serial-tearing bug — keep
// this invariant loud.
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

func (zd *ZoneData) publishedSnapshot() *zoneSnapshot {
	if zd == nil {
		return nil
	}
	return zd.snapshot.Load()
}

func (zd *ZoneData) publishedTransportSignal() *core.RRset {
	snap := zd.publishedSnapshot()
	if snap == nil {
		return nil
	}
	return snap.TransportSignal
}

// soaForResponse returns a response-only SOA RRset from the published snapshot.
func (zd *ZoneData) soaForResponse(apex *OwnerData) core.RRset {
	if snap := zd.publishedSnapshot(); snap != nil && snap.SOA != nil {
		rs := core.RRset{
			Name:   snap.SOA.Hdr.Name,
			Class:  snap.SOA.Hdr.Class,
			RRtype: dns.TypeSOA,
			RRs:    []dns.RR{dns.Copy(snap.SOA)},
		}
		if apex != nil {
			rs.RRSIGs = cloneRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)).RRSIGs
		}
		return rs
	}
	// Fallback (no published snapshot yet): guard a nil apex so a query racing
	// zone initialization cannot panic here. Hot-path callers also SERVFAIL
	// when publishedSnapshot()==nil (see QueryResponder).
	if apex == nil {
		return core.RRset{}
	}
	rs := cloneRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA))
	if len(rs.RRs) > 0 {
		if soa, ok := rs.RRs[0].(*dns.SOA); ok {
			soa.Serial = zd.CurrentSerial
		}
	}
	return rs
}
