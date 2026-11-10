package tdns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// tsigRW is a ResponseWriter whose TsigStatus is settable (nil: the request's
// TSIG verified) and which hands every answer to a channel, since an approved
// update is answered from another goroutine.
type tsigRW struct {
	status error
	ch     chan *dns.Msg
}

func newTsigRW(status error) *tsigRW { return &tsigRW{status: status, ch: make(chan *dns.Msg, 4)} }

func (w *tsigRW) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *tsigRW) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4711}
}
func (w *tsigRW) WriteMsg(m *dns.Msg) error   { w.ch <- m.Copy(); return nil }
func (w *tsigRW) Write(b []byte) (int, error) { return len(b), nil }
func (w *tsigRW) Close() error                { return nil }
func (w *tsigRW) TsigStatus() error           { return w.status }
func (w *tsigRW) TsigTimersOnly(bool)         {}
func (w *tsigRW) Hijack()                     {}

func (w *tsigRW) answer(t *testing.T) *dns.Msg {
	t.Helper()
	select {
	case m := <-w.ch:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
		return nil
	}
}

const tsigTestZoneName = "dyn.example."

// tsigTestZone is a primary zone with a child delegation, TSIG grants for
// three keys, and allow-tsig-updates on unless opts says otherwise.
func tsigTestZone(t *testing.T, opts map[ZoneOption]bool) *ZoneData {
	t.Helper()
	zd := testSnapshotZone(t, tsigTestZoneName, `dyn.example.	3600	IN	SOA	ns.dyn.example. hostmaster.dyn.example. 1 7200 1800 604800 7200
dyn.example.	3600	IN	NS	ns.dyn.example.
ns.dyn.example.	3600	IN	A	192.0.2.53
child.dyn.example.	3600	IN	NS	ns.child.dyn.example.
ns.child.dyn.example.	3600	IN	A	192.0.2.54
`)
	if opts == nil {
		opts = map[ZoneOption]bool{OptAllowTsigUpdates: true}
	}
	zd.Options = opts
	zd.UpdatePolicy.Zone.Type = "none"
	zd.UpdatePolicy.Zone.TTL = 120
	zd.UpdatePolicy.TsigGrants = mustGrants(t, tsigTestZoneName,
		TsigGrantConf{Key: "ddns.", NameType: "zonesub", RRtypes: []string{"ANY"}},
		TsigGrantConf{Key: "acme.", NameType: "subdomain", Name: "_acme-challenge.dyn.example.", RRtypes: []string{"TXT"}},
		TsigGrantConf{Key: "h1.dyn.example.", NameType: "self", RRtypes: []string{"A", "TXT"}},
	)
	return zd
}

func tsigUpdateMsg(t *testing.T, key string, rrs ...string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(tsigTestZoneName)
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("NewRR %q: %v", s, err)
		}
		m.Insert([]dns.RR{rr})
	}
	if key != "" {
		m.SetTsig(key, dns.HmacSHA256, 300, time.Now().Unix())
	}
	return m
}

// runTsigUpdate sends m through UpdateResponder and returns the answer and
// the request the ZoneUpdater was handed, if any. The stand-in updater
// reports every update applied.
func runTsigUpdate(t *testing.T, w *tsigRW, m *dns.Msg) (*dns.Msg, *UpdateRequest, *UpdateStatus) {
	t.Helper()
	updateq := make(chan UpdateRequest, 1)
	got := make(chan UpdateRequest, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case ur := <-updateq:
			got <- ur
			ur.Resp <- ZoneUpdateResult{Applied: true}
		case <-ctx.Done():
		}
	}()
	dur := &DnsUpdateRequest{ResponseWriter: w, Msg: m, Qname: m.Question[0].Name, Status: &UpdateStatus{}}
	_ = UpdateResponder(ctx, dur, updateq)
	ans := w.answer(t)
	select {
	case ur := <-got:
		return ans, &ur, dur.Status
	default:
		return ans, nil, dur.Status
	}
}

func wantRefused(t *testing.T, name string, ans *dns.Msg, ur *UpdateRequest, rcode int, ede uint16) {
	t.Helper()
	if ans.Rcode != rcode {
		t.Errorf("%s: rcode = %s, want %s", name, dns.RcodeToString[ans.Rcode], dns.RcodeToString[rcode])
	}
	found, code, _ := edns0.ExtractEDEFromMsg(ans)
	if !found || code != ede {
		t.Errorf("%s: EDE = %d (found %v), want %d", name, code, found, ede)
	}
	if ur != nil {
		t.Errorf("%s: a refused update reached the ZoneUpdater: %+v", name, ur.Actions)
	}
}

func TestTsigUpdateApproved(t *testing.T) {
	tsigTestZone(t, nil)
	cases := []struct {
		key string
		rrs []string
	}{
		{"ddns.", []string{"host.dyn.example. 60 IN A 192.0.2.10", "host.dyn.example. 60 IN SSHFP 1 2 0123456789abcdef"}},
		{"acme.", []string{`_acme-challenge.dyn.example. 60 IN TXT "token"`}},
		{"H1.dyn.example.", []string{"h1.dyn.example. 60 IN A 192.0.2.11"}},
	}
	for _, c := range cases {
		ans, ur, us := runTsigUpdate(t, newTsigRW(nil), tsigUpdateMsg(t, c.key, c.rrs...))
		if ans.Rcode != dns.RcodeSuccess {
			t.Errorf("key %s: rcode = %s, want NOERROR", c.key, dns.RcodeToString[ans.Rcode])
			continue
		}
		if ur == nil {
			t.Errorf("key %s: approved but never handed to the ZoneUpdater", c.key)
			continue
		}
		if ur.Cmd != "ZONE-UPDATE" || !ur.Authz.isTsig() || ur.Authz.Key != canonicalFqdn(c.key) || len(ur.Actions) != len(c.rrs) {
			t.Errorf("key %s: handed over as %s, authz %+v, %d actions", c.key, ur.Cmd, ur.Authz, len(ur.Actions))
		}
		if ur.InternalUpdate || ur.PreAuthorized {
			t.Errorf("key %s: a TSIG update must not bypass the applier's policy checks", c.key)
		}
		if us.SignatureType != "tsig" || us.SignerName != canonicalFqdn(c.key) {
			t.Errorf("key %s: status %s/%s", c.key, us.SignatureType, us.SignerName)
		}
	}
}

func TestTsigUpdateRefused(t *testing.T) {
	tsigTestZone(t, nil)
	cases := []struct {
		name string
		key  string
		rrs  []string
		ede  uint16
	}{
		{"key without a grant", "other.", []string{"host.dyn.example. 60 IN A 192.0.2.10"}, edns0.EDEZoneUpdatesNotAllowed},
		{"owner outside the grant", "acme.", []string{`www.dyn.example. 60 IN TXT "x"`}, edns0.EDEZoneUpdateOwnerOutsidePolicy},
		{"type outside the grant", "acme.", []string{"_acme-challenge.dyn.example. 60 IN A 192.0.2.1"}, edns0.EDEZoneUpdateRRtypeNotAllowed},
		{"self grant, another name", "h1.dyn.example.", []string{"h2.dyn.example. 60 IN A 192.0.2.1"}, edns0.EDEZoneUpdateOwnerOutsidePolicy},
		{"narrow ANY: DNSKEY", "ddns.", []string{"dyn.example. 60 IN DNSKEY 257 3 13 AAAA"}, edns0.EDEZoneUpdateRRtypeNotAllowed},
		{"one bad record refuses the message", "acme.", []string{`_acme-challenge.dyn.example. 60 IN TXT "ok"`, `www.dyn.example. 60 IN TXT "no"`}, edns0.EDEZoneUpdateOwnerOutsidePolicy},
	}
	for _, c := range cases {
		ans, ur, _ := runTsigUpdate(t, newTsigRW(nil), tsigUpdateMsg(t, c.key, c.rrs...))
		wantRefused(t, c.name, ans, ur, dns.RcodeRefused, c.ede)
	}
}

// allow-tsig-updates is the switch, independent of allow-updates.
func TestTsigUpdateNeedsAllowTsigUpdates(t *testing.T) {
	tsigTestZone(t, map[ZoneOption]bool{OptAllowUpdates: true})
	ans, ur, _ := runTsigUpdate(t, newTsigRW(nil), tsigUpdateMsg(t, "ddns.", "host.dyn.example. 60 IN A 192.0.2.10"))
	wantRefused(t, "allow-updates only", ans, ur, dns.RcodeRefused, edns0.EDEZoneUpdatesNotAllowed)
}

// A TSIG that was not verified (DoH and DoQ cannot) authorizes nothing.
func TestTsigUpdateUnverifiedTsig(t *testing.T) {
	tsigTestZone(t, nil)
	ans, ur, _ := runTsigUpdate(t, newTsigRW(errTsigUnverified), tsigUpdateMsg(t, "ddns.", "host.dyn.example. 60 IN A 192.0.2.10"))
	wantRefused(t, "unverified TSIG", ans, ur, dns.RcodeRefused, dns.ExtendedErrorCodeOther)
}

// Delegation data for a child stays SIG(0).
func TestTsigUpdateRefusesChildDelegationData(t *testing.T) {
	tsigTestZone(t, map[ZoneOption]bool{OptAllowTsigUpdates: true, OptAllowChildUpdates: true})
	ans, ur, _ := runTsigUpdate(t, newTsigRW(nil), tsigUpdateMsg(t, "ddns.", "child.dyn.example. 60 IN DS 12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	wantRefused(t, "child DS over TSIG", ans, ur, dns.RcodeRefused, edns0.EDEZoneUpdatesNotAllowed)
}

// Prerequisites are refused on both paths.
func TestUpdateWithPrerequisitesRefused(t *testing.T) {
	tsigTestZone(t, map[ZoneOption]bool{OptAllowTsigUpdates: true, OptAllowUpdates: true})
	for _, key := range []string{"ddns.", ""} { // TSIG, and unsigned (the SIG(0) path)
		m := tsigUpdateMsg(t, "", "host.dyn.example. 60 IN A 192.0.2.10")
		m.NameNotUsed([]dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "host.dyn.example."}}})
		if key != "" {
			m.SetTsig(key, dns.HmacSHA256, 300, time.Now().Unix())
		}
		ans, ur, _ := runTsigUpdate(t, newTsigRW(nil), m)
		wantRefused(t, "prerequisites, key "+key, ans, ur, dns.RcodeNotImplemented, dns.ExtendedErrorCodeNotSupported)
	}
}

// A message with a SIG RR takes the SIG(0) path even when it also carries a
// TSIG: the grants are not consulted, and SIG(0) validation decides.
func TestSig0AndTsigTakesTheSig0Path(t *testing.T) {
	zd := tsigTestZone(t, map[ZoneOption]bool{OptAllowTsigUpdates: true, OptAllowUpdates: true})
	zd.KeyDB = newTestKeyDB(t) // the SIG(0) path looks the signer up
	m := tsigUpdateMsg(t, "", "host.dyn.example. 60 IN A 192.0.2.10")
	sig := &dns.SIG{RRSIG: dns.RRSIG{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY},
		TypeCovered: 0, Algorithm: dns.ED25519, SignerName: "nosuch.dyn.example.", KeyTag: 1}}
	m.Extra = append(m.Extra, sig)
	m.SetTsig("ddns.", dns.HmacSHA256, 300, time.Now().Unix())
	ans, ur, us := runTsigUpdate(t, newTsigRW(nil), m)
	if us.SignatureType == "tsig" {
		t.Error("a message with a SIG RR was authorized by TSIG")
	}
	if ans.Rcode == dns.RcodeSuccess || ur != nil {
		t.Errorf("an unverifiable SIG(0) update was accepted: rcode %s", dns.RcodeToString[ans.Rcode])
	}
}

func TestUpdateRequestTypeAllowed(t *testing.T) {
	zd := &ZoneData{ZoneName: tsigTestZoneName}
	zd.UpdatePolicy.Zone.RRtypes = map[uint16]bool{dns.TypeA: true}
	grants := mustGrants(t, tsigTestZoneName,
		TsigGrantConf{Key: "k.", NameType: "subdomain", Name: "h.dyn.example.", RRtypes: []string{"SSHFP"}})
	tsig := &UpdateRequest{Authz: &UpdateAuthz{Mech: AuthzTsig, Key: "k.", Grants: grants}}
	sig0 := &UpdateRequest{}
	cases := []struct {
		name  string
		ur    *UpdateRequest
		owner string
		t     uint16
		want  bool
	}{
		{"tsig: granted type outside the SIG(0) list", tsig, "h.dyn.example.", dns.TypeSSHFP, true},
		{"tsig: SIG(0) list does not grant TSIG", tsig, "h.dyn.example.", dns.TypeA, false},
		{"tsig: owner outside the grant", tsig, "x.dyn.example.", dns.TypeSSHFP, false},
		{"sig0: as before", sig0, "x.dyn.example.", dns.TypeA, true},
		{"sig0: as before, denied", sig0, "x.dyn.example.", dns.TypeSSHFP, false},
		{"internal", &UpdateRequest{InternalUpdate: true}, "x.dyn.example.", dns.TypeSSHFP, true},
		{"api", &UpdateRequest{PreAuthorized: true}, "x.dyn.example.", dns.TypeSSHFP, true},
	}
	for _, c := range cases {
		if got := c.ur.typeAllowed(zd, c.owner, c.t); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
