/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The maintainer's three rules for the transport signal (ruling on plan step
// S2, 2026-11-15). A server composes signal responses from zone data, the
// customer zone's and its own zones', not from who it is:
//
//  1. Provisioned records are included by zone data alone, with no identity
//     test and no address test.
//  2. Synthesis from service.transport happens only under names in
//     service.identities, only in the zone that is that name's home, where
//     this server is primary and signer, and only where no records exist at
//     that owner.
//  3. The server never writes into a customer zone.

func noIdentities(t *testing.T) {
	t.Helper()
	prev := Conf.Service.Identities
	Conf.Service.Identities = nil
	t.Cleanup(func() { Conf.Service.Identities = prev })
}

func signalOwners(sigs []core.RRset) map[string]bool {
	names := map[string]bool{}
	for _, rs := range sigs {
		if len(rs.RRs) > 0 {
			names[rs.RRs[0].Header().Name] = true
		}
	}
	return names
}

// Rule 1: a customer's alias to a target in a zone this server serves brings
// the target with it, with no identity configured anywhere.
func TestACustomerAliasToATargetInMyZoneBringsTheTarget(t *testing.T) {
	noIdentities(t)
	const cz = "customer-a.sig.example."
	const pz = "provider-a.sig.example."
	customer, _ := signalTestZone(t, cz, cz+`	3600	IN	NS	ns1.`+cz+`
ns1.`+cz+`	3600	IN	A	192.0.2.1
_dns.ns1.`+cz+`	300	IN	SVCB	0 _dns.ns.`+pz+`
`, "127.0.0.1:53")
	signalTestZone(t, pz, pz+`	3600	IN	NS	ns.`+pz+`
ns.`+pz+`	3600	IN	A	192.0.2.53
_dns.ns.`+pz+`	300	IN	SVCB	1 . oots="dot:30"
`, "127.0.0.1:53")
	got := signalOwners(customer.collectSignalRRsets(customer.publishedSnapshot()))
	if len(got) != 2 || !got["_dns.ns1."+cz] || !got["_dns.ns."+pz] {
		t.Fatalf("the alias and its target in my zone were expected: %v", got)
	}
}

// Rule 1: an alias to another provider's target, in no zone served here,
// goes in alone.
func TestAnAliasToAnotherProvidersTargetGoesAlone(t *testing.T) {
	noIdentities(t)
	const cz = "customer-b.sig.example."
	customer, _ := signalTestZone(t, cz, cz+`	3600	IN	NS	ns1.`+cz+`
ns1.`+cz+`	3600	IN	A	192.0.2.1
_dns.ns1.`+cz+`	300	IN	SVCB	0 _dns.ns.other-provider.example.
`, "127.0.0.1:53")
	got := customer.collectSignalRRsets(customer.publishedSnapshot())
	if len(got) != 1 || !signalOwners(got)["_dns.ns1."+cz] || !svcbHasAlias(got[0]) {
		t.Fatalf("the alias alone was expected: %v", got)
	}
}

// Rule 1: every NS name whose signal is provisioned in a zone served here
// gets it, ns1, ns2 and ns3 alike, in the provider's own zone and in a
// customer zone that names them. No identity, and none of the addresses is
// a listener.
func TestProvisionedSignalsForEveryNSNameAreIncluded(t *testing.T) {
	noIdentities(t)
	const pz = "provider-c.sig.example."
	const cz = "customer-c.sig.example."
	var body, cbody string
	for _, n := range []string{"ns1", "ns2", "ns3"} {
		body += pz + "	3600	IN	NS	" + n + "." + pz + "\n" +
			n + "." + pz + "	3600	IN	A	192.0.2.53\n" +
			"_dns." + n + "." + pz + "	300	IN	SVCB	1 . oots=\"dot:30\"\n"
		cbody += cz + "	3600	IN	NS	" + n + "." + pz + "\n"
	}
	provider, _ := signalTestZone(t, pz, body, "127.0.0.1:53")
	customer, _ := signalTestZone(t, cz, cbody, "127.0.0.1:53")
	for _, zd := range []*ZoneData{provider, customer} {
		got := signalOwners(zd.collectSignalRRsets(zd.publishedSnapshot()))
		if len(got) != 3 || !got["_dns.ns1."+pz] || !got["_dns.ns2."+pz] || !got["_dns.ns3."+pz] {
			t.Fatalf("%s: every NS name's provisioned signal was expected: %v", zd.ZoneName, got)
		}
	}
}

// Rule 2: synthesis only under a name in service.identities, and only in
// that name's home. A name whose address is a listener but which is not an
// identity gets nothing. An identity under a co-hosted child is synthesized
// in the child, not in the parent. A zone that merely names the identity
// gets nothing written into it.
func TestSynthesisIsOnlyUnderIdentitiesInTheirHome(t *testing.T) {
	const pz = "provider-d.sig.example."
	const child = "child." + pz
	const cz = "customer-d.sig.example."
	provider, conf := signalTestZone(t, pz, pz+`	3600	IN	NS	ns1.`+pz+`
`+pz+`	3600	IN	NS	ns2.`+pz+`
ns1.`+pz+`	3600	IN	A	192.0.2.53
ns2.`+pz+`	3600	IN	A	127.0.0.1
`+child+`	3600	IN	NS	ns3.`+child+`
ns3.`+child+`	3600	IN	A	192.0.2.54
`, "127.0.0.1:53")
	childZd, _ := signalTestZone(t, child, child+`	3600	IN	NS	ns3.`+child+`
ns3.`+child+`	3600	IN	A	192.0.2.54
`, "127.0.0.1:53")
	customer, _ := signalTestZone(t, cz, cz+`	3600	IN	NS	ns1.`+pz+`
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + pz, "ns3." + child}
	conf.Service.Transport.Signal = "dot:50"
	before := customer.publishedSnapshot()
	for _, zd := range []*ZoneData{customer, childZd, provider} {
		runTransportSignalPass(zd, conf)
	}

	if !served(provider, "_dns.ns1."+pz, dns.TypeSVCB) {
		t.Fatal("no signal synthesized for an identity in its home zone")
	}
	if served(provider, "_dns.ns2."+pz, dns.TypeSVCB) {
		t.Fatal("a signal was synthesized for a name that is a listener address but not an identity")
	}
	if !served(childZd, "_dns.ns3."+child, dns.TypeSVCB) {
		t.Fatal("no signal synthesized in the co-hosted child, the identity's home")
	}
	if getOwnerFrom(provider.publishedSnapshot(), "_dns.ns3."+child) != nil {
		t.Fatal("the parent got a signal below its zone cut for an identity whose home is the child")
	}
	if customer.publishedSnapshot() != before {
		t.Fatal("the pass published into a zone that only names the identity")
	}
	got := signalOwners(customer.collectSignalRRsets(customer.publishedSnapshot()))
	if len(got) != 1 || !got["_dns.ns1."+pz] {
		t.Fatalf("the customer's responses did not carry the identity's signal from its home: %v", got)
	}
}

// Rule 3: nothing is written into a customer zone, whatever is or is not
// there: not for its in-zone NS name whose address is a listener, not for
// an identity it names, and not over the operator's alias.
func TestTheSignalPassNeverWritesIntoACustomerZone(t *testing.T) {
	const pz = "provider-e.sig.example."
	const cz = "customer-e.sig.example."
	provider, conf := signalTestZone(t, pz, pz+`	3600	IN	NS	ns1.`+pz+`
ns1.`+pz+`	3600	IN	A	127.0.0.1
`, "127.0.0.1:53")
	customer, _ := signalTestZone(t, cz, cz+`	3600	IN	NS	ns1.`+cz+`
`+cz+`	3600	IN	NS	ns2.`+cz+`
`+cz+`	3600	IN	NS	ns1.`+pz+`
ns1.`+cz+`	3600	IN	A	127.0.0.1
ns2.`+cz+`	3600	IN	A	127.0.0.1
_dns.ns2.`+cz+`	300	IN	SVCB	0 _dns.ns1.`+pz+`
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + pz}
	conf.Service.Transport.Signal = "dot:50"
	before := customer.publishedSnapshot()
	for _, zd := range []*ZoneData{customer, provider} {
		runTransportSignalPass(zd, conf)
	}

	if customer.publishedSnapshot() != before {
		t.Fatal("the pass published into a customer zone")
	}
	if served(customer, "_dns.ns1."+cz, dns.TypeSVCB) {
		t.Fatal("a signal was written into a customer zone for its NS name with a listener address")
	}
	if !served(provider, "_dns.ns1."+pz, dns.TypeSVCB) {
		t.Fatal("no signal synthesized in the provider's own zone")
	}
	got := signalOwners(customer.collectSignalRRsets(customer.publishedSnapshot()))
	if len(got) != 2 || !got["_dns.ns2."+cz] || !got["_dns.ns1."+pz] {
		t.Fatalf("the customer's alias and the provider's signal were expected: %v", got)
	}
}

// Rule 2 at home: a zone this server is not the primary and signer of gets
// nothing synthesized, even as an identity's home. A signal provisioned in
// it is still included (rule 1).
func TestNoSynthesisInAHomeThisServerDoesNotSign(t *testing.T) {
	const z = "signed-elsewhere.sig.example."
	logs := captureSignalLog(t)
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	NS	ns2.`+z+`
`+z+`	3600	IN	DNSKEY	257 3 15 O3xbJlGx2Ol+f3mu57551r87qbeE1OrPA8j49W8JaPw=
ns1.`+z+`	3600	IN	A	127.0.0.1
ns2.`+z+`	3600	IN	A	127.0.0.1
_dns.ns2.`+z+`	300	IN	SVCB	1 . oots="dot:30"
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z}
	before := zd.publishedSnapshot()
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if zd.publishedSnapshot() != before || served(zd, "_dns.ns1."+z, dns.TypeSVCB) {
		t.Fatal("a signal was synthesized into a zone signed by someone else")
	}
	if !strings.Contains(logs.String(), "not its primary and signer") {
		t.Fatalf("no info line for the home this server does not sign:\n%s", logs.String())
	}
	got := signalOwners(zd.collectSignalRRsets(zd.publishedSnapshot()))
	if len(got) != 1 || !got["_dns.ns2."+z] {
		t.Fatalf("the provisioned signal was not included: %v", got)
	}
}

// What the pass stored for a name that is no longer an identity at home is
// withdrawn after a restart: left in place, rule 1 would serve it as if it
// were provisioned. A signal the operator has since replaced is kept.
func TestTheSignalPassWithdrawsItsSignalFromANameNoLongerAnIdentity(t *testing.T) {
	const z = "withdraw.sig.example."
	const body = z + `	3600	IN	NS	ns1.` + z + `
` + z + `	3600	IN	NS	ns2.` + z + `
` + z + `	3600	IN	NS	ns3.` + z + `
ns1.` + z + `	3600	IN	A	192.0.2.1
ns2.` + z + `	3600	IN	A	192.0.2.2
ns3.` + z + `	3600	IN	A	192.0.2.3
`
	kdb := newTestKeyDB(t)
	zd, conf := signalTestZone(t, z, body, "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z, "ns2." + z, "ns3." + z}
	conf.Service.Transport.Signal = "dot:50"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	var persisted []string
	for _, n := range []string{"ns1", "ns2"} {
		for _, rr := range svcbRecords(zd, "_dns."+n+"."+z) {
			persisted = append(persisted, rr.String())
		}
	}
	// ns3's signal was replaced by the operator before the restart.
	persisted = append(persisted, `_dns.ns3.`+z+` 300 IN SVCB 1 . oots="doq:10"`)

	// A new process, the same KeyDB, and ns2 and ns3 dropped from the
	// identities.
	logs := captureSignalLog(t)
	zd2, conf2 := signalTestZone(t, z, body+strings.Join(persisted, "\n")+"\n", "127.0.0.1:53")
	zd2.KeyDB = kdb
	conf2.Service.Identities = []string{"ns1." + z}
	conf2.Service.Transport.Signal = "dot:20"
	if err := zd2.CreateTransportSignalRRs(conf2); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd2, "_dns.ns1."+z); len(got) != 1 || !strings.Contains(got[0].String(), "dot:20") {
		t.Fatalf("the identity's signal was not rewritten: %v", got)
	}
	if getOwnerFrom(zd2.publishedSnapshot(), "_dns.ns2."+z) != nil {
		t.Fatal("the pass's own signal for a name that is no longer an identity was not withdrawn")
	}
	if !strings.Contains(logs.String(), "withdrew the signal") {
		t.Fatalf("no info line for the withdrawn signal:\n%s", logs.String())
	}
	if got := svcbRecords(zd2, "_dns.ns3."+z); len(got) != 1 || !strings.Contains(got[0].String(), "doq:10") {
		t.Fatalf("the operator's replacement was withdrawn with the record: %v", got)
	}
	for _, n := range []string{"ns2", "ns3"} {
		if _, ok, _ := kdb.GetTransportSignalStored(z, "_dns."+n+"."+z); ok {
			t.Fatalf("the record for _dns.%s outlived the withdrawal", n)
		}
	}
}

// A withdrawal writes the zone, so it happens only where this server is
// primary and signer, as synthesis does. A former primary that restarts as a
// secondary of the zone, with its signal in the zone and its record in the
// KeyDB, and the name no longer an identity, changes nothing and keeps the
// record.
func TestAFormerPrimaryWithdrawsNothingAsASecondary(t *testing.T) {
	const z = "demoted.sig.example."
	const body = z + `	3600	IN	NS	ns1.` + z + `
ns1.` + z + `	3600	IN	A	192.0.2.1
`
	kdb := newTestKeyDB(t)
	zd, conf := signalTestZone(t, z, body, "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = "dot:50"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	stored := svcbRecords(zd, "_dns.ns1."+z)
	var persisted []string
	for _, rr := range stored {
		persisted = append(persisted, rr.String())
	}

	prevApp := Globals.App.Type
	Globals.App.Type = AppTypeAuth
	t.Cleanup(func() { Globals.App.Type = prevApp })
	zd2, conf2 := signalTestZone(t, z, body+strings.Join(persisted, "\n")+"\n", "127.0.0.1:53")
	zd2.KeyDB = kdb
	zd2.ZoneType = Secondary
	conf2.Service.Transport.Signal = "dot:50"
	before := zd2.publishedSnapshot()
	if err := zd2.CreateTransportSignalRRs(conf2); err != nil {
		t.Fatal(err)
	}
	if zd2.publishedSnapshot() != before || !sameRecords(svcbRecords(zd2, "_dns.ns1."+z), stored) {
		t.Fatalf("a secondary withdrew the signal from a zone it does not originate: %v", svcbRecords(zd2, "_dns.ns1."+z))
	}
	if _, ok, _ := kdb.GetTransportSignalStored(z, "_dns.ns1."+z); !ok {
		t.Fatal("a secondary dropped the record of the signal it stored as primary")
	}
}
