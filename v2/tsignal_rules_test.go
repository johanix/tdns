package tdns

import (
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// signalTestZone is a zone with the transport-signal option, registered, with
// the NS names and extra records the test writes. The server's SVCB and the
// listeners are set for the test and restored after it.
func signalTestZone(t *testing.T, name, body string, listeners ...string) (*ZoneData, *Config) {
	t.Helper()
	zone := name + `	3600	IN	SOA	ns1.` + name + ` hostmaster.` + name + ` 1 7200 1800 604800 7200
` + body
	zd := testZone(t, name, zone)
	zd.Options = map[ZoneOption]bool{OptAddTransportSignal: true, OptAllowUpdates: true, OptAllowApiUpdates: true}
	zd.UpdatePolicy = policyAllowing(dns.TypeSVCB, dns.TypeTXT)
	registerZones(t, zd)
	t.Cleanup(func() { zd.stopPublisher(); zd.joinPublisher() })

	prevSVCB, prevListeners := Globals.ServerSVCB, Conf.Listeners.Addresses
	Globals.ServerSVCB = &dns.SVCB{Hdr: dns.RR_Header{Name: "_dns.server.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300}, Priority: 1, Target: "."}
	Conf.Listeners.Addresses = listeners
	t.Cleanup(func() { Globals.ServerSVCB, Conf.Listeners.Addresses = prevSVCB, prevListeners })
	conf := &Config{}
	conf.Service.Transport.Type = "svcb"
	conf.Listeners.Addresses = listeners
	return zd, conf
}

func svcbRecords(zd *ZoneData, owner string) []dns.RR {
	snap := zd.publishedSnapshot()
	od := getOwnerFrom(snap, owner)
	if od == nil {
		return nil
	}
	return od.RRtypes.GetOnlyRRSet(dns.TypeSVCB).RRs
}

// One server with two identities at home in the zone gets a signal under
// each: the pass visits every identity and does not stop at the first.
func TestTheSignalPassVisitsEveryIdentityAtHome(t *testing.T) {
	const z = "two.sig.example."
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	NS	ns2.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
ns2.`+z+`	3600	IN	A	127.0.0.2
`, "127.0.0.1:53", "127.0.0.2:53")
	conf.Service.Identities = []string{"ns1." + z, "ns2." + z}
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if !served(zd, "_dns.ns1."+z, dns.TypeSVCB) || !served(zd, "_dns.ns2."+z, dns.TypeSVCB) {
		t.Fatalf("one signal per identity expected: ns1=%v ns2=%v", served(zd, "_dns.ns1."+z, dns.TypeSVCB), served(zd, "_dns.ns2."+z, dns.TypeSVCB))
	}
}

// An operator's alias at one identity's owner is left alone and does not stop
// the pass from speaking for the server's other identity.
func TestAnOperatorAliasDoesNotStopTheSignalPass(t *testing.T) {
	const z = "alias.sig.example."
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	NS	ns2.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
ns2.`+z+`	3600	IN	A	127.0.0.1
_dns.ns1.`+z+`	300	IN	SVCB	0 _dns.ns.provider.example.
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z, "ns2." + z}
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if rrs := svcbRecords(zd, "_dns.ns1."+z); len(rrs) != 1 || rrs[0].(*dns.SVCB).Priority != 0 {
		t.Fatalf("the operator's alias was not left alone: %v", rrs)
	}
	if !served(zd, "_dns.ns2."+z, dns.TypeSVCB) {
		t.Fatal("the pass stopped at the alias and did not speak for the server's other identity")
	}
}

// A zone that is signed by someone else gets no signal from a server that
// does not sign it, even as an identity's home: nothing stored, and no
// unsigned fallback beside the snapshot either (rule 2: synthesis only where
// this server is primary and signer).
func TestASignedZoneThisServerDoesNotSignGetsNoStoredSignal(t *testing.T) {
	const z = "signed.sig.example."
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	DNSKEY	257 3 15 O3xbJlGx2Ol+f3mu57551r87qbeE1OrPA8j49W8JaPw=
ns1.`+z+`	3600	IN	A	127.0.0.1
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z}
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if served(zd, "_dns.ns1."+z, dns.TypeSVCB) {
		t.Fatal("an unsigned signal was stored into a zone signed by someone else")
	}
	snap := zd.publishedSnapshot()
	if snap == nil || snap.signalSynth["_dns.ns1."+z] != nil {
		t.Fatal("an unsigned fallback was kept beside the snapshot")
	}
	if got := zd.collectSignalRRsets(snap); len(got) != 0 {
		t.Fatalf("a signal was injected from no zone data: %d RRsets", len(got))
	}
}

// The option on a zone none of whose NS names has a signal here or is an
// identity draws a warning and publishes nothing: a hidden primary should
// not carry it.
func TestTheSignalPassWarnsWhenNoNSNameIsThisServer(t *testing.T) {
	const z = "hidden.sig.example."
	var logs syncBuffer
	prev := lgDns
	lgDns = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lgDns = prev })
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	192.0.2.1
`, "127.0.0.1:53")
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if served(zd, "_dns.ns1."+z, dns.TypeSVCB) {
		t.Fatal("a signal was stored for a name that is not this server's")
	}
	if !strings.Contains(logs.String(), "nothing to publish") {
		t.Fatalf("no warning for the option on a zone that does not name this server:\n%s", logs.String())
	}
}

// An alias target is chased as written (RFC 9460 section 3): the provider's
// signal under its _dns. label is found when the alias names it, and a bare
// target finds nothing.
func TestAnAliasTargetIsChasedAsWritten(t *testing.T) {
	const z = "vanity.sig.example."
	const pz = "provider.example."
	zd, _ := signalTestZone(t, z, z+`	3600	IN	NS	ns2.`+z+`
ns2.`+z+`	3600	IN	A	127.0.0.1
_dns.ns2.`+z+`	300	IN	SVCB	0 _dns.ns.provider.example.
`, "127.0.0.1:53")
	provider := testZone(t, pz, pz+`	3600	IN	SOA	ns.`+pz+` hostmaster.`+pz+` 1 7200 1800 604800 7200
`+pz+`	3600	IN	NS	ns.`+pz+`
ns.`+pz+`	3600	IN	A	127.0.0.1
_dns.ns.`+pz+`	300	IN	SVCB	1 . alpn=dot
`)
	registerZones(t, provider)
	got := zd.collectSignalRRsets(zd.publishedSnapshot())
	names := map[string]bool{}
	for _, rs := range got {
		for _, rr := range rs.RRs {
			names[rr.Header().Name] = true
		}
	}
	if !names["_dns.ns2."+z] || !names["_dns.ns."+pz] {
		t.Fatalf("the alias and the signal at its target were expected: %v", names)
	}

	// The same alias with a bare target: hosted, so the alias is injected,
	// but nothing is found at the bare name.
	const z2 = "vanity2.sig.example."
	zd2, _ := signalTestZone(t, z2, z2+`	3600	IN	NS	ns2.`+z2+`
ns2.`+z2+`	3600	IN	A	127.0.0.1
_dns.ns2.`+z2+`	300	IN	SVCB	0 ns.provider.example.
`, "127.0.0.1:53")
	got = zd2.collectSignalRRsets(zd2.publishedSnapshot())
	if len(got) != 1 || len(got[0].RRs) != 1 || got[0].RRs[0].Header().Name != "_dns.ns2."+z2 {
		t.Fatalf("a bare target was chased with a prefix added: %d RRsets", len(got))
	}
}

// An alias is included by zone data alone (rule 1): whatever the vanity
// name's addresses, and with its target in no zone served here, the alias
// goes in alone.
func TestAnAliasIsIncludedByZoneDataAlone(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "192.0.2.1"} {
		z := "alias-" + strings.ReplaceAll(addr, ".", "-") + ".sig.example."
		zd, _ := signalTestZone(t, z, z+`	3600	IN	NS	ns2.`+z+`
ns2.`+z+`	3600	IN	A	`+addr+`
_dns.ns2.`+z+`	300	IN	SVCB	0 _dns.ns.elsewhere.example.
`, "127.0.0.1:53")
		if got := zd.collectSignalRRsets(zd.publishedSnapshot()); len(got) != 1 || !svcbHasAlias(got[0]) {
			t.Fatalf("%s: the alias was not included alone: %v", addr, got)
		}
		if !served(zd, "_dns.ns2."+z, dns.TypeSVCB) {
			t.Fatal("the alias is zone content and must answer a direct query")
		}
	}
}

// A mixed AliasMode/ServiceMode RRset is refused at load and by an update.
func TestAMixedSVCBRRsetIsRefused(t *testing.T) {
	const z = "mixed.sig.example."
	bad := &ZoneData{ZoneName: z, ZoneStore: MapZone, Logger: log.New(os.Stderr, "", 0)}
	_, _, err := bad.ReadZoneData(z+`	3600	IN	SOA	ns1.`+z+` hostmaster.`+z+` 1 7200 1800 604800 7200
`+z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
_dns.ns1.`+z+`	300	IN	SVCB	0 _dns.ns.provider.example.
_dns.ns1.`+z+`	300	IN	SVCB	1 . alpn=dot
`, true)
	if err == nil || !strings.Contains(err.Error(), "AliasMode") {
		t.Fatalf("a mixed SVCB RRset was loaded: err=%v", err)
	}

	const z2 = "mixed2.sig.example."
	zd, _ := signalTestZone(t, z2, z2+`	3600	IN	NS	ns1.`+z2+`
ns1.`+z2+`	3600	IN	A	127.0.0.1
_dns.ns1.`+z2+`	300	IN	SVCB	0 _dns.ns.provider.example.
`, "127.0.0.1:53")
	kdb := newTestKeyDB(t)
	ur := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: z2, InternalUpdate: true,
		Actions: []dns.RR{
			txTestRR(t, "other."+z2+` 300 IN TXT "rides along"`),
			txTestRR(t, "_dns.ns1."+z2+" 300 IN SVCB 1 . alpn=dot"),
		}}
	updated, _, err := zd.applyZoneUpdate(ur, kdb, nil)
	if err == nil || !strings.Contains(err.Error(), "AliasMode") || updated {
		t.Fatalf("an update that would mix an SVCB RRset was not refused to the sender: updated=%v err=%v", updated, err)
	}
	if rrs := svcbRecords(zd, "_dns.ns1."+z2); len(rrs) != 1 || rrs[0].(*dns.SVCB).Priority != 0 {
		t.Fatalf("a refused update changed the SVCB RRset: %v", rrs)
	}
	if served(zd, "other."+z2, dns.TypeTXT) {
		t.Fatal("a refused update applied its other records")
	}

	// The pre-check follows the applier's rules: the owner's spelling does
	// not get a second RRset past it, and a class NONE delete matches the
	// record whatever its TTL.
	ur = UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: z2, InternalUpdate: true,
		Actions: []dns.RR{txTestRR(t, "_DNS.NS1."+strings.ToUpper(z2)+" 300 IN SVCB 1 . alpn=dot")}}
	if _, _, err := zd.applyZoneUpdate(ur, kdb, nil); err == nil || !strings.Contains(err.Error(), "AliasMode") {
		t.Fatalf("a differently spelled owner got a mixed RRset past the pre-check: %v", err)
	}
	none := txTestRR(t, "_dns.ns1."+z2+" 0 IN SVCB 0 _dns.ns.provider.example.")
	none.Header().Class = dns.ClassNONE
	if err := zd.refuseMixedSvcbUpdateLocked([]dns.RR{none, txTestRR(t, "_dns.ns1."+z2+" 300 IN SVCB 1 . alpn=dot")}); err != nil {
		t.Fatalf("a class NONE delete with another TTL did not count as removing the alias: %v", err)
	}

	// Replacing the alias by a ServiceMode record in one update is not a
	// mix: the RRset is deleted before the add.
	del := &dns.SVCB{Hdr: dns.RR_Header{Name: "_dns.ns1." + z2, Rrtype: dns.TypeSVCB, Class: dns.ClassANY}}
	ur = UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: z2, InternalUpdate: true,
		Actions: []dns.RR{del, txTestRR(t, "_dns.ns1."+z2+" 300 IN SVCB 1 . alpn=dot")}}
	if _, _, err := zd.applyZoneUpdate(ur, kdb, nil); err != nil {
		t.Fatalf("a replacement was refused: %v", err)
	}
	if rrs := svcbRecords(zd, "_dns.ns1."+z2); len(rrs) != 1 || rrs[0].(*dns.SVCB).Priority != 1 {
		t.Fatalf("the replacement did not land: %v", rrs)
	}
}

// The join, not the arm: a real tdns-auth secondary that may not originate
// content, its options through the normalizer. The option is kept, and
// nothing is stored into the zone it mirrors or kept beside it, even as an
// identity's home (rule 2). A signal in the mirrored data is included as it
// came (rule 1).
func TestANonOriginatingSecondaryKeepsTheOptionAndStoresNothing(t *testing.T) {
	const z = "mirror.sig.example."
	prevApp := Globals.App.Type
	Globals.App.Type = AppTypeAuth
	t.Cleanup(func() { Globals.App.Type = prevApp })
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	NS	ns2.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
ns2.`+z+`	3600	IN	A	127.0.0.1
_dns.ns2.`+z+`	300	IN	SVCB	1 . oots="dot:30"
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z}
	zd.ZoneType = Secondary
	effective, _, suppressed, msg := normalizeOptionsForRole(AppTypeAuth, Secondary, zd.Options, "")
	if !effective[OptAddTransportSignal] || suppressed[OptAddTransportSignal] {
		t.Fatalf("the normalizer stripped add-transport-signal from a secondary: %v %q", suppressed, msg)
	}
	zd.Options = effective
	if zoneMayOriginateContent(zd) {
		t.Fatal("the test zone may originate content; it does not exercise the join")
	}
	before := zd.publishedSnapshot()
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if served(zd, "_dns.ns1."+z, dns.TypeSVCB) {
		t.Fatal("a signal was stored into a zone the server may not modify")
	}
	snap := zd.publishedSnapshot()
	if snap != before {
		t.Fatal("the pass published into a mirrored zone")
	}
	if got := zd.collectSignalRRsets(snap); len(got) != 1 || !signalOwners(got)["_dns.ns2."+z] {
		t.Fatalf("the signal in the mirrored data was not included as it came: %v", got)
	}
}
