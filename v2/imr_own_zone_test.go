/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #842: a server authoritative for a zone, whose resolver forwards "." to an
// upstream, asked that upstream about its own zone. The trust anchor
// initialisation for the zone fetched the zone's DNSKEY RRset through the
// forward, and the coherence check on a child's DS UPDATE fetched the child's
// DS, and the zone's DNSKEY to validate it, the same way. The server answers
// those questions itself now, from the zone it publishes.
//
// The rig: parent.example. is hosted here, signed, and delegates
// child.parent.example. with a DS. The resolver forwards "." to an upstream
// that answers SERVFAIL to everything, and holds a stub for the child pointing
// at a double of the child's server, which serves the child's signed DNSKEY
// RRset. The upstream must never be asked about a name in the parent zone.

const (
	ownParent = "parent.example."
	ownChild  = "child.parent.example."

	// ownChildKEY is the public key of the KEY the child's server publishes at
	// the child's apex: the child's SIG(0) key, as at-apex looks it up.
	ownChildKEY = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
)

const ownParentZone = `parent.example.	3600	IN	SOA	ns.parent.example. hostmaster.parent.example. 1 7200 1800 604800 300
parent.example.	3600	IN	NS	ns.parent.example.
ns.parent.example.	3600	IN	A	192.0.2.1
www.parent.example.	3600	IN	A	192.0.2.2
child.parent.example.	3600	IN	NS	ns.child.parent.example.
ns.child.parent.example.	3600	IN	A	192.0.2.3
`

type ownZoneRig struct {
	imr      *Imr
	parent   *ZoneData
	childDS  *dns.DS
	upLog    *upstreamLog // the forward's upstream
	childLog *upstreamLog // the child's server
}

func newOwnZoneRig(t *testing.T) *ownZoneRig {
	t.Helper()
	childKey := newFwdSecKey(t, ownChild)
	childDS := childKey.dnskey.ToDS(dns.SHA256)
	parent, _ := signedTestZone(t, ownParent, ownParentZone+childDS.String()+"\n", false)

	// SERVFAIL to every question: the forward has nothing usable to say about
	// the parent zone, which is the server's to answer anyway.
	upLog := &upstreamLog{}
	upAddr, upPort := startLoggedSignedForwardUpstream(t, nil, upLog)

	childLog := &upstreamLog{}
	childAddr, childPort := startLoggedSignedForwardUpstream(t, map[string]*dns.Msg{
		ownChild + " DNSKEY":     {Answer: childKey.sign(t, childKey.dnskey)},
		ownChild + " KEY":        {Answer: childKey.sign(t, fwdSecRR(t, ownChild+" 300 IN KEY 256 3 15 "+ownChildKEY))},
		"www." + ownChild + " A": {Answer: childKey.sign(t, fwdSecRR(t, "www."+ownChild+" 300 IN A 192.0.2.55"))},
	}, childLog)

	imr := newForwardTestImr(t, rootForward(upAddr, upPort))
	imr.DnskeyCache = imr.Cache.DnskeyCache // as InitImrEngine wires it
	imr.FamilyTracker = cache.NewFamilyTracker(10*time.Minute, 10*time.Minute, 30*time.Second, 5)
	// The stub's server is reached through the cache's shared per-transport
	// clients (fixed port); the forward has its own client.
	port := strconv.Itoa(int(childPort))
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	if err := imr.Cache.AddStub(ownChild, []cache.AuthServer{
		{Name: "ns." + ownChild, Addrs: []string{childAddr}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.setZoneTable(imr.ForwardZones(), []string{ownChild}, nil)

	return &ownZoneRig{imr: imr, parent: parent, childDS: childDS, upLog: upLog, childLog: childLog}
}

// kskDS is the DS of a signed zone's KSK, as a trust anchor names it.
func kskDS(t *testing.T, zd *ZoneData) *dns.DS {
	t.Helper()
	keys := getRRsetFrom(zd.publishedSnapshot(), zd.ZoneName, dns.TypeDNSKEY)
	if keys == nil {
		t.Fatalf("test setup: the signed zone %s has no DNSKEY RRset", zd.ZoneName)
	}
	for _, rr := range keys.RRs {
		if dk, ok := rr.(*dns.DNSKEY); ok && dk.Flags&dns.SEP != 0 {
			return dk.ToDS(dns.SHA256)
		}
	}
	t.Fatalf("test setup: the signed zone %s has no KSK", zd.ZoneName)
	return nil
}

// requireUpstreamNotAsked fails the test if the forward's upstream was asked
// about a name in zone. The DS at the apex is the zone above's to answer, and
// would be allowed; nothing here asks for it.
func requireUpstreamNotAsked(t *testing.T, logr *upstreamLog, zone string) {
	t.Helper()
	logr.mu.Lock()
	queries := append([]upstreamQuery(nil), logr.queries...)
	logr.mu.Unlock()
	for _, q := range queries {
		if !dns.IsSubDomain(zone, q.Qname) || (core.EqualNames(q.Qname, zone) && q.Qtype == dns.TypeDS) {
			continue
		}
		t.Errorf("the forward's upstream was asked %s %s, in %s, which this server is authoritative for",
			q.Qname, dns.TypeToString[q.Qtype], zone)
	}
}

// The trust anchor initialisation for the server's own zone takes the zone's
// DNSKEY RRset from the zone. It fetched it through the forward, and failed
// with "no usable response for 'parent.example. DNSKEY'".
func TestOwnZoneTrustAnchorComesFromTheZone(t *testing.T) {
	rig := newOwnZoneRig(t)

	conf := &Config{}
	conf.Imr.TrustAnchorDS = kskDS(t, rig.parent).String()
	if err := rig.imr.initializeImrTrustAnchors(context.Background(), conf); err != nil {
		t.Fatalf("trust anchor initialization for the server's own zone: %v", err)
	}
	if c := rig.imr.Cache.Get(ownParent, dns.TypeDNSKEY); c == nil || c.State != cache.ValidationStateSecure {
		t.Errorf("%s DNSKEY after trust anchor initialization: %+v, want it cached Secure", ownParent, c)
	}
	requireUpstreamNotAsked(t, rig.upLog, ownParent)
}

// At start-up the resolver comes up before the zones load, and the trust
// anchor initialisation runs before the zone it anchors is there to answer. It
// must not ask the forward in the meantime; once the zone has loaded, its keys
// come from the zone.
func TestOwnZoneTrustAnchorBeforeTheZoneLoads(t *testing.T) {
	rig := newOwnZoneRig(t)
	ds := kskDS(t, rig.parent)
	Zones.Remove(ownParent) // configured, not loaded yet

	conf := &Config{}
	conf.Imr.TrustAnchorDS = ds.String()
	conf.Internal.AllZones = []string{ownParent}
	if err := rig.imr.initializeImrTrustAnchors(context.Background(), conf); err != nil {
		t.Fatalf("trust anchor initialization before the server's own zone has loaded: %v", err)
	}
	requireUpstreamNotAsked(t, rig.upLog, ownParent)

	Zones.Set(ownParent, rig.parent) // loaded
	resp, err := rig.imr.ImrQuery(context.Background(), ownParent, dns.TypeDNSKEY, dns.ClassINET, nil)
	if err != nil || resp.RRset == nil || !resp.Validated {
		t.Fatalf("%s DNSKEY once the zone has loaded: %+v (err %v), want it from the zone, secure", ownParent, resp, err)
	}
	requireUpstreamNotAsked(t, rig.upLog, ownParent)
}

// The same with no forward, before priming: the resolver knows no servers for
// anything, and needs none for its own zone. It gave up with "no known servers
// for parent.example. to fetch DNSKEY".
func TestOwnZoneTrustAnchorNeedsNoServers(t *testing.T) {
	parent, _ := signedTestZone(t, ownParent, ownParentZone, false)
	imr := newForwardTestImr(t, nil)
	imr.DnskeyCache = imr.Cache.DnskeyCache // as InitImrEngine wires it

	conf := &Config{}
	conf.Imr.TrustAnchorDS = kskDS(t, parent).String()
	if err := imr.initializeImrTrustAnchors(context.Background(), conf); err != nil {
		t.Fatalf("trust anchor initialization for the server's own zone: %v", err)
	}
	// Not forwarded, so the anchor zone's NS RRset is validated too.
	for _, qtype := range []uint16{dns.TypeDNSKEY, dns.TypeNS} {
		if c := imr.Cache.Get(ownParent, qtype); c == nil || c.State != cache.ValidationStateSecure {
			t.Errorf("%s %s after trust anchor initialization: %+v, want it cached Secure", ownParent, dns.TypeToString[qtype], c)
		}
	}
}

// What the resolver asks about its own zone -- the zone's keys, data in it,
// the DS of a child, names and types that do not exist -- is answered from the
// zone, validated against the zone's own keys. A name below the child's cut is
// the child's, and is asked of the child's server as before.
func TestOwnZoneQuestionsAreAnsweredFromTheZone(t *testing.T) {
	rig := newOwnZoneRig(t)
	ctx := context.Background()

	cases := []struct {
		qname  string
		qtype  uint16
		want   string // the answer's first record's rdata, or "" for a denial
		denial cache.CacheContext
	}{
		{ownParent, dns.TypeDNSKEY, "", 0},
		{"www." + ownParent, dns.TypeA, "192.0.2.2", 0},
		{ownChild, dns.TypeDS, rig.childDS.Digest, 0},
		{"nosuch." + ownParent, dns.TypeA, "", cache.ContextNXDOMAIN},
		{"www." + ownParent, dns.TypeMX, "", cache.ContextNoErrNoAns},
	}
	for _, c := range cases {
		what := c.qname + " " + dns.TypeToString[c.qtype]
		resp, err := rig.imr.ImrQuery(ctx, c.qname, c.qtype, dns.ClassINET, nil)
		if err != nil {
			t.Errorf("%s: %v", what, err)
			continue
		}
		if resp.Error {
			t.Errorf("%s: %s", what, resp.ErrorMsg)
			continue
		}
		if c.denial != 0 {
			if resp.Denial != c.denial || resp.RRset != nil {
				t.Errorf("%s: denial %s, rrset %v; want %s", what,
					cache.CacheContextToString[resp.Denial], resp.RRset, cache.CacheContextToString[c.denial])
			}
		} else {
			if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
				t.Errorf("%s: no answer (denial %s)", what, cache.CacheContextToString[resp.Denial])
				continue
			}
			if c.want != "" {
				if got := rdataOf(resp.RRset.RRs[0]); !strings.EqualFold(got, c.want) {
					t.Errorf("%s: answer %q, want %q", what, got, c.want)
				}
			}
		}
		if !resp.Validated {
			t.Errorf("%s: validation state %s, want secure: the zone's own keys sign it",
				what, cache.ValidationStateToString[resp.ValidationState])
		}
	}
	requireUpstreamNotAsked(t, rig.upLog, ownParent)

	// Below the cut: the child's data, which the parent would answer with a
	// referral. It goes to the child's server.
	resp, err := rig.imr.ImrQuery(ctx, "www."+ownChild, dns.TypeA, dns.ClassINET, nil)
	if err != nil || resp.RRset == nil || len(resp.RRset.RRs) == 0 || rdataOf(resp.RRset.RRs[0]) != "192.0.2.55" {
		t.Errorf("www.%s A: %+v (err %v), want the child server's 192.0.2.55", ownChild, resp, err)
	}
	if len(rig.childLog.find("www."+ownChild, dns.TypeA)) == 0 {
		t.Errorf("www.%s A was not asked of the child's server", ownChild)
	}
}

// The coherence check on a child's DS UPDATE validates the child's DNSKEY RRset
// through the resolver, and that needs the child's DS and the parent's keys:
// both the parent's own data. Taken from the forward, the child came back
// unvalidated and the UPDATE was refused (EDE 544).
func TestOwnZoneCoherenceCheckValidatesTheChild(t *testing.T) {
	rig := newOwnZoneRig(t)

	// A second DS, for a key the child does not publish yet: the start of a
	// KSK roll. The DS already published still matches the child's key.
	next := newFwdSecKey(t, ownChild).dnskey.ToDS(dns.SHA256)
	if err := rig.parent.CheckDelegationCoherenceForUpdate([]dns.RR{next}, imrDnskeyFetcher(rig.imr)); err != nil {
		t.Fatalf("coherence check on adding a DS for %s: %v", ownChild, err)
	}
	requireUpstreamNotAsked(t, rig.upLog, ownParent)
}

// Which questions are the zone's own: its data, and the DS of a child, which
// the parent holds. Not the child's data -- the delegation's NS, its glue,
// anything below the cut -- nor the zone's own DS, which the zone above holds,
// nor anything while the zone is not answering queries.
func TestOwnZoneForQuestion(t *testing.T) {
	rig := newOwnZoneRig(t)
	cases := []struct {
		qname string
		qtype uint16
		own   bool
	}{
		{ownParent, dns.TypeDNSKEY, true},
		{ownParent, dns.TypeSOA, true},
		{"WWW.Parent.Example.", dns.TypeA, true},
		{"nosuch." + ownParent, dns.TypeA, true},
		{"nosuch." + ownParent, dns.TypeDS, true},
		{ownChild, dns.TypeDS, true},
		{ownChild, dns.TypeNS, false},
		{"ns." + ownChild, dns.TypeA, false},
		{"www." + ownChild, dns.TypeA, false},
		{"www." + ownChild, dns.TypeDS, false},
		{ownParent, dns.TypeDS, false},
		{"elsewhere.example.", dns.TypeA, false},
		{ownParent, dns.TypeANY, false},
	}
	for _, c := range cases {
		if got := rig.imr.ownZoneForQuestion(c.qname, c.qtype) != nil; got != c.own {
			t.Errorf("ownZoneForQuestion(%s %s) = %v, want %v", c.qname, dns.TypeToString[c.qtype], got, c.own)
		}
	}

	rig.parent.SetError(ConfigError, "test: a service-impacting error")
	defer rig.parent.SetError(NoError, "")
	if rig.imr.ownZoneForQuestion("www."+ownParent, dns.TypeA) != nil {
		t.Error("a zone the query handler would SERVFAIL for is still answered from")
	}
}

// An unsigned zone the server hosts is answered from the zone too, and its data
// is Insecure: nothing signs it, and nobody above it is asked.
func TestOwnUnsignedZoneIsAnsweredInsecure(t *testing.T) {
	const plain = "plain.example."
	testSnapshotZone(t, plain, `plain.example.	3600	IN	SOA	ns.plain.example. hostmaster.plain.example. 1 7200 1800 604800 300
plain.example.	3600	IN	NS	ns.plain.example.
ns.plain.example.	3600	IN	A	192.0.2.1
www.plain.example.	3600	IN	A	192.0.2.9
`)
	upLog := &upstreamLog{}
	upAddr, upPort := startLoggedSignedForwardUpstream(t, nil, upLog)
	imr := newForwardTestImr(t, rootForward(upAddr, upPort))
	ctx := context.Background()

	resp, err := imr.ImrQuery(ctx, "www."+plain, dns.TypeA, dns.ClassINET, nil)
	if err != nil || resp.RRset == nil || len(resp.RRset.RRs) == 0 || rdataOf(resp.RRset.RRs[0]) != "192.0.2.9" {
		t.Fatalf("www.%s A: %+v (err %v), want 192.0.2.9 from the zone", plain, resp, err)
	}
	if resp.Validated || resp.ValidationState != cache.ValidationStateInsecure {
		t.Errorf("www.%s A: validation state %s, want insecure", plain, cache.ValidationStateToString[resp.ValidationState])
	}
	resp, err = imr.ImrQuery(ctx, "nosuch."+plain, dns.TypeA, dns.ClassINET, nil)
	if err != nil || resp.Denial != cache.ContextNXDOMAIN {
		t.Errorf("nosuch.%s A: %+v (err %v), want NXDOMAIN from the zone", plain, resp, err)
	} else if resp.Validated {
		t.Errorf("nosuch.%s A: an unsigned zone's denial came back secure", plain)
	}
	requireUpstreamNotAsked(t, upLog, plain)
}

// rdataOf is an RR's rdata as text: what follows its header.
func rdataOf(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.DS:
		return v.Digest
	}
	s := rr.String()
	return s[len(rr.Header().String()):]
}
