/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The ddns writer: how a childsync-proxy gets records into the parent zone it
// is a secondary of. An RFC 2136 UPDATE over TCP, TSIG-signed, to the zone's
// primaries, carrying the actions it was handed. It makes ONE attempt and
// classifies the outcome; retrying is the push engine's job, and the engine
// recomputes what to send from the store rather than replaying a message.
//
// Design: docs/2026-09-08-childsync-proxy.md §5.1, §5.6, D-5.

type ddnsParentZoneWriter struct {
	zd            *ZoneData
	store         DelegationStore
	targets       []string // addr:port; empty means the zone's upstreams, read at write time
	keyName       string
	allowInsecure bool
}

func newDdnsParentZoneWriter(spec DelegationBackendSpec, store DelegationStore, zd *ZoneData) (*ddnsParentZoneWriter, error) {
	if zd == nil {
		return nil, fmt.Errorf("delegation backend %q: the ddns writer needs a zone and there is none", spec.Name)
	}
	var targets []string
	for _, t := range spec.Conf.DDNS.Targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(t); err != nil {
			t = net.JoinHostPort(t, "53")
		}
		targets = append(targets, t)
	}
	return &ddnsParentZoneWriter{
		zd:            zd,
		store:         store,
		targets:       targets,
		keyName:       spec.Conf.DDNS.Key,
		allowInsecure: spec.Conf.DDNS.AllowInsecure,
	}, nil
}

func (w *ddnsParentZoneWriter) Name() string { return DelegationWriterDDNS }

// WriteRejected reports that the parent primary answered the UPDATE and said
// no. A transport failure is an ordinary error; this is the other thing, and
// the push engine treats the two differently: a transport failure or a
// SERVFAIL is retried with backoff, a REFUSED or NOTAUTH is the primary's
// policy rejecting us -- an operator problem -- and is not hammered.
type WriteRejected struct {
	Rcode      int
	EDEFound   bool
	EDECode    uint16
	EDEMessage string
}

func (e *WriteRejected) Error() string {
	s := fmt.Sprintf("the parent primary rejected the UPDATE with %s", dns.RcodeToString[e.Rcode])
	if e.EDEFound {
		s += fmt.Sprintf(" (EDE %d: %s)", e.EDECode, e.EDEMessage)
	}
	return s
}

// Transient reports whether waiting and retrying can change the answer.
func (e *WriteRejected) Transient() bool {
	return e.Rcode == dns.RcodeServerFailure
}

// Write sends the actions as one UPDATE to the first target that answers.
func (w *ddnsParentZoneWriter) Write(ctx context.Context, parentZone string, actions []dns.RR, desc string) error {
	if len(actions) == 0 {
		return nil
	}
	if err := w.boundToDelegationNames(parentZone, actions); err != nil {
		return err
	}

	targets := w.targets
	if len(targets) == 0 {
		targets = w.zd.upstreamAddrs()
	}
	if len(targets) == 0 {
		return fmt.Errorf("ddns writer for %s: no ddns.targets configured and the zone has no primaries to fall back on", parentZone)
	}

	m := new(dns.Msg)
	m.SetUpdate(parentZone)
	m.Ns = append([]dns.RR(nil), actions...)

	// Resolved and stamped immediately before the exchange: that split exists
	// so a message that waited in a queue does not go out with a stale
	// timestamp and earn a BADTIME.
	provider, algorithm, err := TsigMaterialForPeer(w.keyName, &Conf)
	if err != nil {
		return fmt.Errorf("ddns writer for %s: %w", parentZone, err)
	}
	if provider == nil {
		if !w.allowInsecure {
			return fmt.Errorf("ddns writer for %s: refusing to send an unsigned UPDATE to the parent primary;"+
				" set ddns.key, or ddns.allow-insecure for a lab", parentZone)
		}
		lg.Warn("ddns writer: sending an UNSIGNED UPDATE to the parent primary (ddns.allow-insecure)",
			"zone", parentZone, "targets", targets)
	} else {
		StampTsigForPeer(m, w.keyName, algorithm)
	}

	lg.Info("ddns writer: pushing to the parent primary", "zone", parentZone,
		"actions", len(actions), "desc", desc, "targets", targets, "signed", provider != nil)
	rcode, ur, err := sendUpdateVia(ctx, m, parentZone, targets, provider)
	if err != nil {
		return fmt.Errorf("ddns writer for %s: %w", parentZone, err)
	}
	if rcode == dns.RcodeSuccess {
		return nil
	}
	return &WriteRejected{Rcode: rcode, EDEFound: ur.EDEFound, EDECode: ur.EDECode, EDEMessage: ur.EDEMessage}
}

// upstreamAddrs is the zone's primaries as addr:port, copied under the lock:
// the refresh engine rewrites zd.Upstreams in place when it re-resolves a
// hostname primary.
func (zd *ZoneData) upstreamAddrs() []string {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	out := make([]string, 0, len(zd.Upstreams))
	for _, u := range zd.Upstreams {
		if u.Addr != "" {
			out = append(out, u.Addr)
		}
	}
	return out
}

// boundToDelegationNames is D-5: the writer holds DDNS write authority over
// the parent zone, the primary's own update-policy should bound it, but the
// primary is someone else's configuration and a tdns bug must not be able to
// rewrite a parent apex even against a permissive primary. So every action's
// owner must be one of
//
//   - a child delegation point of the parent, or a name below one (glue);
//   - one of this agent's own advertisement names: _dsync.<parent>, the
//     configured NOTIFY/UPDATE/API targets, the bootstrap SVCB name.
//
// A refusal is an internal-invariant ERROR naming the owner, in the spirit of
// the KEY guard in ZoneUpdater. Defence in depth, not the load-bearing gate.
//
// A delegation point is recognised from any of three places, because a cut
// can be in any of them and in none of the others: the served zone (an
// existing delegation), the store (a delegation accepted but not yet
// transferred back), or the actions themselves (the update that creates it).
func (w *ddnsParentZoneWriter) boundToDelegationNames(parentZone string, actions []dns.RR) error {
	adv := advertisementNames(parentZone)
	for _, rr := range actions {
		owner := rr.Header().Name
		if adv[core.CanonicalizeName(owner)] {
			continue
		}
		if core.EqualNames(owner, parentZone) || !dns.IsSubDomain(parentZone, owner) {
			return w.refuse(parentZone, owner, "not below the parent apex")
		}
		if !w.underADelegationPoint(parentZone, owner, actions) {
			return w.refuse(parentZone, owner, "not at or below a delegation point of the parent")
		}
	}
	return nil
}

func (w *ddnsParentZoneWriter) refuse(parentZone, owner, why string) error {
	lg.Error("ddns writer: refusing to write outside the parent's delegation names (invariant violation)",
		"zone", parentZone, "owner", owner, "why", why)
	return fmt.Errorf("ddns writer for %s: refusing to write %s: %s", parentZone, owner, why)
}

// underADelegationPoint walks up from owner to (not including) the apex and
// asks, for each ancestor and owner itself, whether it is a cut.
func (w *ddnsParentZoneWriter) underADelegationPoint(parentZone, owner string, actions []dns.RR) bool {
	labels := dns.SplitDomainName(owner)
	parentLabels := dns.CountLabel(parentZone)
	for i := 0; i < len(labels)-parentLabels; i++ {
		candidate := dns.Fqdn(strings.Join(labels[i:], "."))
		if w.isDelegationPoint(parentZone, candidate, actions) {
			return true
		}
	}
	return false
}

func (w *ddnsParentZoneWriter) isDelegationPoint(parentZone, name string, actions []dns.RR) bool {
	// The update that creates the delegation names the cut itself.
	for _, rr := range actions {
		switch rr.Header().Rrtype {
		case dns.TypeNS, dns.TypeDS:
			if core.EqualNames(rr.Header().Name, name) {
				return true
			}
		}
	}
	// A delegation the served zone carries.
	if w.zd != nil {
		w.zd.mu.Lock()
		owner, err := w.zd.GetOwner(name)
		var cut bool
		if err == nil && owner != nil {
			_, cut = owner.RRtypes.Get(dns.TypeNS)
		}
		w.zd.mu.Unlock()
		if cut {
			return true
		}
	}
	// A delegation the store holds and the zone does not serve yet.
	if w.store != nil {
		if data, err := w.store.GetDelegationData(parentZone, name); err == nil && len(data[name]) > 0 {
			return true
		}
	}
	return false
}

// advertisementNames are the owner names this agent publishes for its own
// DSYNC service: the _dsync owner and every configured scheme target. The
// receiver KEY and the bootstrap SVCB live at the UPDATE target.
func advertisementNames(parentZone string) map[string]bool {
	names := map[string]bool{core.CanonicalizeName(dsyncOwnerName(parentZone)): true}
	dsc := ChildSyncConfig()
	if dsyncSchemeConfigured(dsc.Schemes, "notify") && dsc.Notify.Target != "" {
		names[core.CanonicalizeName(expandDsyncTemplate(dsc.Notify.Target, parentZone))] = true
	}
	if t := DsyncUpdateTargetName(parentZone); t != "" && dsyncSchemeConfigured(dsc.Schemes, "update") {
		names[core.CanonicalizeName(t)] = true
	}
	if t := DsyncApiTargetName(parentZone); t != "" {
		names[core.CanonicalizeName(t)] = true
	}
	return names
}

// RenderNsupdateBlock renders actions as an nsupdate(1) script an operator
// can apply at the primary by hand: what the manual writer shows, and what
// `zone childsync proxy-status` prints when the advertisement is waiting for
// publication.
func RenderNsupdateBlock(parentZone string, targets []string, keyName string, actions []dns.RR) string {
	var b strings.Builder
	if len(targets) > 0 {
		fmt.Fprintf(&b, "server %s\n", targets[0])
	}
	if keyName != "" && keyName != NOKEY {
		fmt.Fprintf(&b, "; sign with TSIG key %s (nsupdate -k <keyfile>)\n", keyName)
	}
	fmt.Fprintf(&b, "zone %s\n", parentZone)
	lines := make([]string, 0, len(actions))
	for _, rr := range actions {
		switch rr.Header().Class {
		case dns.ClassANY:
			lines = append(lines, fmt.Sprintf("update delete %s %s", rr.Header().Name, dns.TypeToString[rr.Header().Rrtype]))
		case dns.ClassNONE:
			c := dns.Copy(rr)
			c.Header().Class = dns.ClassINET
			c.Header().Ttl = 0
			lines = append(lines, "update delete "+c.String())
		default:
			lines = append(lines, "update add "+rr.String())
		}
	}
	sort.Stable(sort.StringSlice(lines))
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	b.WriteString("send\n")
	return b.String()
}
