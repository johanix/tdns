/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The checks, in order. The numbers are the eleven groups README.md lists;
 * the design sections are in the comments. app1 and app2 are application
 * clients (apiserver.app-clients), op is an operator's certificate, "the
 * operator" is tdns-ncli over the local socket, and the audit view is the
 * socket read directly.
 */
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// The rig's zones. run.sh writes the static ones into the daemon config.
const (
	S1   = "s1.test."     // static primary, api-owner: cert:app1, allow-api-updates
	S2   = "s2.test."     // static primary, no grant, allow-api-updates
	SIG  = "signed.test." // static primary, no grant, signed here (online-signing)
	C1   = "cat1.test."   // static catalog zone, api-owner: cert:app1
	C2   = "cat2.test."   // static catalog zone, no grant
	C3   = "cat3.test."   // app1's catalog zone, from catalog create
	Z1   = "z1.test."     // app1's secondary, handed to app2 in group 9
	Z2   = "z2.test."     // app2's secondary
	Z8   = "z8.test."     // app1's secondary, added naming another API owner
	Z9   = "z9.test."     // app1's attempt with app2's key: never created
	P1   = "p1.test."     // app1's primary, deleted by app1
	P2   = "p2.test."     // app2's primary, with a DNSSEC key
	P3   = "p3.test."     // app1's primary, deleted by the operator with --keep-keys
	P4   = "p4.test."     // app1's primary, deleted right after its add
	AO1  = "ao1.test."    // the operator's, added over the socket: API owner api
	OZ1  = "oz1.test."    // op's, added over its certificate: API owner cert:op
	KZ   = "kz.test."     // added by a caller on the API key: API owner api
	SUB  = "sub.s2.test." // app1's zone inside S2 (question Q2)
	Z6   = "z6.test."     // app1's zone on its own existing key, given inline
	Z7   = "z7.test."     // app1's attempt with app2's key inline: never created
	KSP2 = "spare.app2."  // app2's unused key, which app1 tries to name inline
	GRP  = "svc1"         // a group in C1
	K1   = "k1.app1."     // app1's inline key on Z1
	K2   = "k2.app1."     // app1's key from tsig-mgmt add
	K3   = "k3.app1."     // tsig-mgmt add naming another owner
	K4   = "k4.app1."     // tsig-mgmt generate
	K5   = "k5.app1."     // tsig-mgmt import
	K6   = "k6.app1."     // tsig-mgmt bulk-import
	KAP2 = "app2-key."    // app2's inline key on Z2
	KOP  = "op-key."      // op's inline key on OZ1

	app1Owner = "cert:app1"
	app2Owner = "cert:app2"
)

// refusal texts, as the code words the design's refusals
var (
	notOwnConfig = []string{"API owner is config, not cert:app1"}
	notOwnApi    = []string{"API owner is api, not cert:app1"}
	notOwnCert   = []string{"not a zone of API owner cert:app1"}
	notForApps   = []string{"not available to application clients"}
	needsAdmin   = []string{"needs admin"}
)

func (s *suite) secondary() []tdns.PeerConf {
	return []tdns.PeerConf{{Addr: s.o.Primary, Key: tdns.NOKEY}}
}

func (s *suite) run() {
	s.setup()
	s.check1ZoneAdd()
	s.check2Visibility()
	s.check3ZoneWrites()
	s.check4Catalog()
	s.check5WholeServer()
	s.check6Tsig()
	s.check7Dnssec()
	s.check8DeleteAndKeys()
	s.check9Isolation()
	s.check10Operator()
	s.check11ApiKey()
	s.notesDesignSilent()
}

// setup: who is who, and the zones and keys of the others that app1 must
// not reach.
func (s *suite) setup() {
	for i, c := range []*client{s.app1, s.app2} {
		resp, o := c.ping()
		s.expect(fmt.Sprintf("S.%d", i+1), c.who+" is an application client", o.OK && strings.Contains(resp.Auth, "application client"),
			fmt.Sprintf("ping: %s", orMsg(resp.Auth, o)))
	}
	resp, o := s.op.ping()
	s.expect("S.3", "op is an operator, not an application client",
		o.OK && strings.Contains(resp.Auth, "authenticated as op (read-write)") && !strings.Contains(resp.Auth, "application client"),
		fmt.Sprintf("ping: %s", orMsg(resp.Auth, o)))

	_, o = s.op.zone(tdns.ZonePost{Command: "add", Zone: OZ1, Primaries: s.secondary(), TsigName: KOP, TsigSecret: s.secret(KOP)})
	s.ok("S.4", "op adds "+OZ1+" with inline key "+KOP, o, s.zoneOwner(OZ1, "cert:op"), s.tsigOwner(KOP, "cert:op"))

	out, err := s.adm.run("auth", "zone", "add", "-z", AO1, "--primaries", s.o.Primary)
	s.ok("S.5", "the operator adds "+AO1+" over the socket (tdns-ncli)", cmdOutcome(out, err), s.zoneOwner(AO1, "api"))

	_, o = s.app2.zone(tdns.ZonePost{Command: "add", Zone: Z2, Primaries: s.secondary(), TsigName: KAP2, TsigSecret: s.secret(KAP2)})
	s.ok("S.6", "app2 adds "+Z2+" with inline key "+KAP2, o, s.zoneOwner(Z2, app2Owner), s.tsigOwner(KAP2, app2Owner))

	_, o = s.app2.zone(tdns.ZonePost{Command: "add", Zone: P2, ZoneType: "primary", Template: s.o.Template})
	s.ok("S.7", "app2 adds primary "+P2, o, s.zoneOwner(P2, app2Owner))
	_, o = s.app2.keystore(dnssecGenerate(P2))
	s.ok("S.8", "app2 generates a DNSSEC key for "+P2, o, s.dnssecCount(P2, 1))
}

// 1. zone add (design 4.3, 4.4): the zone and its inline TSIG key take the
// caller as their API owner.
func (s *suite) check1ZoneAdd() {
	_, o := s.app1.zone(tdns.ZonePost{Command: "add", Zone: Z1, Primaries: s.secondary(), TsigName: K1, TsigSecret: s.secret(K1)})
	s.ok("1.1", "app1 adds secondary "+Z1+" with inline TSIG key "+K1, o)
	s.holds("1.2", Z1+" has API owner cert:app1", "audit: API owner cert:app1, primary uses "+K1,
		s.zoneOwner(Z1, app1Owner), s.primariesAre(Z1, s.o.Primary+"/"+K1))
	s.holds("1.3", K1+" has API owner cert:app1", "audit: API owner cert:app1", s.tsigOwner(K1, app1Owner))
}

// 2. Visibility (design 4.5, decision 5): an application sees only its own
// zones.
func (s *suite) check2Visibility() {
	own := []string{C1, S1, Z1}
	resp, o := s.app1.zone(tdns.ZonePost{Command: "list-zones"})
	got := keys(resp.Zones)
	s.expect("2.1", "app1 list-zones shows its own zones only", o.OK && sameSet(got, own),
		fmt.Sprintf("got %s; expected %s (C1 is granted to app1)", list(got), list(own)), o.Msg)

	resp, o = s.app1.zone(tdns.ZonePost{Command: "list-dynamic"})
	got = keys(resp.Zones)
	s.expect("2.2", "app1 list-dynamic shows its own dynamic zones only", o.OK && sameSet(got, []string{Z1}),
		fmt.Sprintf("got %s; expected %s (S1 is static, so not in list-dynamic)", list(got), Z1), o.Msg)

	_, o = s.app1.zone(tdns.ZonePost{Command: "get-name", Zone: S2, UpdateName: "www." + S2})
	s.refused("2.3", "app1 get-name in "+S2+" (config's)", o, notOwnConfig)
	_, o = s.app1.zone(tdns.ZonePost{Command: "get-name", Zone: Z2, UpdateName: Z2})
	s.refused("2.4", "app1 get-name in "+Z2+" (app2's)", o, notOwnCert)
	_, o = s.app1.zone(tdns.ZonePost{Command: "show-nsec-chain", Zone: AO1})
	s.refused("2.5", "app1 show-nsec-chain of "+AO1+" (api's)", o, notOwnApi)
	_, o = s.app1.zone(tdns.ZonePost{Command: "list-zones", Zone: S2})
	s.refused("2.6", "app1 zone desc of "+S2, o, notOwnConfig)
	_, o = s.app1.zone(tdns.ZonePost{Command: "get-name", Zone: OZ1, UpdateName: OZ1})
	s.refused("2.7", "app1 get-name in "+OZ1+" (op's)", o, notOwnCert)
	_, o = s.app1.zone(tdns.ZonePost{Command: "get-name", Zone: S1, UpdateName: "www." + S1})
	s.ok("2.8", "app1 get-name in its own "+S1, o)

	ks, o := s.app1.keystore(tdns.KeystorePost{Command: "list-algorithms"})
	s.expect("2.9", "app1 keystore list-algorithms is open", o.OK && len(ks.Algorithms) > 0,
		orMsg(fmt.Sprintf("%d algorithms", len(ks.Algorithms)), o), o.Msg)
	ks, o = s.app1.keystore(tdns.KeystorePost{Command: "list-policies"})
	s.expect("2.10", "app1 keystore list-policies is open", o.OK, orMsg(fmt.Sprintf("%d policies", len(ks.Policies)), o), o.Msg)

	o = s.app1.get("/rollover/status?zone=" + S2)
	s.refused("2.11", "app1 rollover status of "+S2+" (config's)", o, notOwnConfig)
}

// 3. Zone writes (design 4.3, 4.5).
func (s *suite) check3ZoneWrites() {
	p2 := []tdns.PeerConf{{Addr: s.o.Primary2, Key: K1}}
	_, o := s.app1.zone(tdns.ZonePost{Command: "modify", Zone: Z1, Primaries: p2})
	s.ok("3.1", "app1 zone modify "+Z1, o, s.primariesAre(Z1, s.o.Primary2+"/"+K1))

	rr := "app." + S1 + " 300 IN A 192.0.2.53"
	_, o = s.app1.zone(tdns.ZonePost{Command: "update", Zone: S1, UpdateVerb: "addrr", UpdateRRs: []string{rr}})
	s.ok("3.2", "app1 zone update in "+S1+" (granted static zone)", o, s.publishes(S1, "app."+S1, "A", "192.0.2.53"))

	out := "intruder." + S2 + " 300 IN A 192.0.2.66"
	_, o = s.app1.zone(tdns.ZonePost{Command: "update", Zone: S1, UpdateVerb: "addrr", UpdateRRs: []string{out}})
	s.refused("3.3", "app1 update of "+S1+" carrying an RR in "+S2, o,
		[]string{"is not in zone " + S1, "is not in the zone"}, s.nothingAt(S2, "intruder."+S2))

	_, o = s.app1.zone(tdns.ZonePost{Command: "delete", Zone: S1})
	s.refused("3.4", "app1 zone delete "+S1+" (static, granted)", o, []string{"is not API-managed"}, s.zoneOwner(S1, app1Owner))

	rr2 := "app1." + S2 + " 300 IN A 192.0.2.54"
	_, o = s.app1.zone(tdns.ZonePost{Command: "update", Zone: S2, UpdateVerb: "addrr", UpdateRRs: []string{rr2}})
	s.refused("3.5", "app1 zone update in "+S2+" (config's)", o, notOwnConfig, s.nothingAt(S2, "app1."+S2))
	_, o = s.app1.zone(tdns.ZonePost{Command: "bump", Zone: S2})
	s.refused("3.6", "app1 zone bump "+S2, o, notOwnConfig)

	aoPrim := s.o.Primary + "/" + tdns.NOKEY
	_, o = s.app1.zone(tdns.ZonePost{Command: "modify", Zone: AO1, Primaries: []tdns.PeerConf{{Addr: s.o.Primary2, Key: tdns.NOKEY}}})
	s.refused("3.7", "app1 zone modify "+AO1+" (api's)", o, notOwnApi, s.primariesAre(AO1, aoPrim))
	_, o = s.app1.zone(tdns.ZonePost{Command: "delete", Zone: AO1})
	s.refused("3.8", "app1 zone delete "+AO1+" (api's)", o, notOwnApi, s.zoneOwner(AO1, "api"))

	z2Prim := s.o.Primary + "/" + KAP2
	_, o = s.app1.zone(tdns.ZonePost{Command: "modify", Zone: Z2, Primaries: []tdns.PeerConf{{Addr: s.o.Primary2, Key: tdns.NOKEY}}})
	s.refused("3.9", "app1 zone modify "+Z2+" (app2's)", o, notOwnCert, s.primariesAre(Z2, z2Prim))
	_, o = s.app1.zone(tdns.ZonePost{Command: "delete", Zone: Z2})
	s.refused("3.10", "app1 zone delete "+Z2+" (app2's)", o, notOwnCert, s.zoneOwner(Z2, app2Owner))
	_, o = s.app1.zone(tdns.ZonePost{Command: "update", Zone: Z2, UpdateVerb: "addrr", UpdateRRs: []string{"x." + Z2 + " 300 IN A 192.0.2.55"}})
	s.refused("3.11", "app1 zone update in "+Z2+" (app2's)", o, notOwnCert)
	_, o = s.app1.zone(tdns.ZonePost{Command: "add", Zone: Z2, Primaries: s.secondary()})
	s.refused("3.12", "app1 zone add of "+Z2+", which exists (app2's)", o, []string{"already exists"}, s.zoneOwner(Z2, app2Owner))
	_, o = s.app1.zone(tdns.ZonePost{Command: "delete", Zone: OZ1})
	s.refused("3.13", "app1 zone delete "+OZ1+" (op's)", o, notOwnCert, s.zoneOwner(OZ1, "cert:op"))

	// The owner is the caller's, whatever the request says (4.3).
	_, o = s.app1.zone(tdns.ZonePost{Command: "add", Zone: Z8, Primaries: s.secondary(), ApiOwner: app2Owner})
	s.ok("3.14", "app1 zone add "+Z8+" naming API owner cert:app2 in the request", o, s.zoneOwner(Z8, app1Owner))
	_, o = s.app1.zone(tdns.ZonePost{Command: "delete", Zone: Z8})
	s.ok("3.15", "app1 zone delete of its own "+Z8, o, s.zoneAbsent(Z8))

	// delegation export (4.5: "delegation status/export: own zone only").
	// The daemon returns the data and the client writes it (#1191), so no
	// Outfile is sent. The operator's answer is the control. s1.test. has
	// no delegation backend here, so that answer is the daemon's error, not
	// data. Until #1191 is in the stack, B refuses export to application
	// clients (AppRefused). After that it is AppOwnZone, and app1 must get
	// the operator's answer for its own zone.
	name316 := "app1 delegation export of its own " + S1 + " (design 4.5: own zone only)"
	_, oop := s.op.delegation(tdns.DelegationPost{Command: "export", Zone: S1})
	opData := exportData(oop)
	if oop.OK && opData != "" {
		// Written by the client, as tdns-ncli del export --outfile does.
		file := filepath.Join(s.o.Scratch, "s1-delegation.zone")
		if err := os.WriteFile(file, []byte(opData), 0o644); err == nil {
			os.Remove(file)
		}
	}
	_, o = s.app1.delegation(tdns.DelegationPost{Command: "export", Zone: S1})
	if !o.OK && strings.Contains(o.Msg, "delegation export: not available to application clients") {
		s.expect("3.16", name316, true,
			"refused: "+firstLine(o.Msg)+" (AppRefused until #1191 is in the stack, then AppOwnZone)")
	} else {
		same := o.OK == oop.OK && o.Msg == oop.Msg && exportData(o) == opData
		s.expect("3.16", name316, same,
			fmt.Sprintf("app1 got %q (%d bytes of data), op got %q (%d bytes)",
				firstLine(o.Msg), len(exportData(o)), firstLine(oop.Msg), len(opData)))
	}
	_, o = s.app1.delegation(tdns.DelegationPost{Command: "status", Zone: S2})
	s.refused("3.17", "app1 delegation status of "+S2+" (config's)", o, notOwnConfig)

	// The zone a command acts on is the one checked (R1), however the
	// name is spelled.
	_, o = s.app1.zone(tdns.ZonePost{Command: "delete", Zone: strings.ToUpper(Z2)})
	s.refused("3.18", "app1 zone delete "+strings.ToUpper(Z2)+" (app2's, upper case)", o, []string{"not a zone of API owner cert:app1"},
		s.zoneOwner(Z2, app2Owner))
	_, o = s.app1.zone(tdns.ZonePost{Command: "modify", Zone: strings.TrimSuffix(Z2, "."),
		Primaries: []tdns.PeerConf{{Addr: s.o.Primary2, Key: tdns.NOKEY}}})
	s.refused("3.19", "app1 zone modify "+strings.TrimSuffix(Z2, ".")+" (app2's, no final dot)", o,
		[]string{"not a zone of API owner cert:app1"}, s.primariesAre(Z2, z2Prim))
	o = s.app1.postRaw("/rollover/asap", map[string]string{"zone": P2})
	s.refused("3.20", "app1 rollover asap of "+P2+" (app2's)", o, notOwnCert)
}

// 4. Catalog (design 4.5): member and catalog zone must both be the caller's.
func (s *suite) check4Catalog() {
	_, o := s.app1.catalog(tdns.CatalogPost{Command: "zone-add", CatalogZone: C1, Zone: Z1})
	s.ok("4.1", "app1 catalog zone-add "+Z1+" into "+C1+" (granted)", o, s.member(C1, Z1, true))
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "zone-add", CatalogZone: C2, Zone: Z1})
	s.refused("4.2", "app1 catalog zone-add "+Z1+" into "+C2+" (config's)", o, notOwnConfig, s.member(C2, Z1, false))
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "zone-add", CatalogZone: C1, Zone: Z2})
	s.refused("4.3", "app1 catalog zone-add "+Z2+" (app2's) into "+C1, o, notOwnCert, s.member(C1, Z2, false))
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "zone-list", CatalogZone: C2})
	s.refused("4.4", "app1 catalog zone-list of "+C2, o, notOwnConfig)

	cr, o := s.app1.catalog(tdns.CatalogPost{Command: "zone-list", CatalogZone: C1})
	s.expect("4.5", "app1 catalog zone-list of its own "+C1+" shows it whole", o.OK && slices.Contains(keys(cr.Zones), Z1),
		orMsg("members "+list(keys(cr.Zones)), o), o.Msg)
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "create", CatalogZone: C3})
	s.ok("4.6", "app1 catalog create "+C3, o, s.zoneOwner(C3, app1Owner))
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "delete", CatalogZone: C1})
	s.refused("4.7", "app1 catalog delete "+C1+" (static, granted)", o, []string{"config-file zone and cannot be deleted"},
		s.zoneOwner(C1, app1Owner))
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "delete", CatalogZone: C3})
	s.ok("4.8", "app1 catalog delete of its own "+C3, o, s.zoneAbsent(C3))

	// A group on Z1 in C1, while app1 owns both: group 9 removes it after
	// Z1 has gone to app2.
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "group-add", CatalogZone: C1, Group: GRP})
	s.ok("4.9", "app1 catalog group-add "+GRP+" to its own "+C1, o)
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "zone-group-add", CatalogZone: C1, Zone: Z1, Group: GRP})
	s.ok("4.10", "app1 catalog zone-group-add "+GRP+" to its "+Z1+" in "+C1, o, s.memberGroup(C1, Z1, GRP, true))
}

// 5. Whole-server commands are refused (design 4.5).
func (s *suite) check5WholeServer() {
	_, o := s.app1.config(tdns.ConfigPost{Command: "reload"})
	s.refused("5.1", "app1 config reload", o, notForApps)

	before, err := s.au.scannerPolling()
	if err != nil {
		s.expect("5.2", "app1 scanner poll on", false, err.Error())
	} else {
		cmd := "on"
		if before {
			cmd = "off"
		}
		_, o = s.app1.scannerPoll(cmd)
		s.refused("5.2", "app1 scanner poll "+cmd, o, notForApps, s.polling(before))
	}

	_, o = s.app1.imr("imr-flush")
	s.refused("5.3", "app1 imr flush", o, notForApps)
}

// 6. TSIG keys (design 4.4, 4.6, 4.7).
func (s *suite) check6Tsig() {
	resp, o := s.app1.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "list"})
	var names []string
	for _, k := range resp.TsigKeys {
		names = append(names, k.Name)
	}
	leaked := s.leakedSecrets(o.Raw)
	s.expect("6.1", "app1 tsig list: its own keys, no secret", o.OK && sameSet(names, []string{K1}) && len(leaked) == 0,
		fmt.Sprintf("keys %s; secrets in the reply: %s", list(names), list(leaked)), o.Msg)

	_, o = s.app1.keystore(tsigPost("add", K2, s.secret(K2)))
	s.ok("6.2", "app1 tsig add "+K2, o, s.tsigOwner(K2, app1Owner))

	_, o = s.app1.keystore(tsigPost("add", KOP, "c2FtZSBuYW1lLCBhbm90aGVyIHNlY3JldCwgb3Atb3du"))
	s.refused("6.3", "app1 tsig add "+KOP+" (op's name) with another secret", o,
		[]string{"exists with another secret or algorithm"}, s.tsigOwner(KOP, "cert:op"), s.tsigSecretKept(KOP))
	_, o = s.app1.keystore(tsigPost("add", KAP2, "c2FtZSBuYW1lLCBhbm90aGVyIHNlY3JldCwgYXBwMm93bg=="))
	s.refused("6.4", "app1 tsig add "+KAP2+" (app2's name) with another secret", o,
		[]string{"exists with another secret or algorithm"}, s.tsigOwner(KAP2, app2Owner), s.tsigSecretKept(KAP2))

	_, o = s.app1.keystore(tsigPost("add", KAP2, s.secrets[KAP2]))
	s.ok("6.5", "app1 tsig add of an identical "+KAP2+" is a no-op", o, s.tsigOwner(KAP2, app2Owner),
		func() string {
			if !strings.Contains(o.Msg, "unchanged") {
				return "the reply does not say the key is unchanged"
			}
			return ""
		})
	_, o = s.app1.keystore(tsigPost("delete", KAP2, ""))
	s.refused("6.6", "app1 tsig delete "+KAP2+" after the no-op add", o, []string{"not found"}, s.tsigOwner(KAP2, app2Owner))

	_, o = s.app1.keystore(tsigPost("delete", K2, ""))
	s.ok("6.7", "app1 tsig delete its unused "+K2, o, s.tsigAbsent(K2))
	_, o = s.app1.keystore(tsigPost("delete", K1, ""))
	s.refused("6.8", "app1 tsig delete "+K1+", which "+Z1+" uses", o, []string{"is referenced by"}, s.tsigOwner(K1, app1Owner))
	_, o = s.app1.keystore(tsigPost("delete", KOP, ""))
	s.refused("6.9", "app1 tsig delete "+KOP+" (op's)", o, []string{"not found"}, s.tsigOwner(KOP, "cert:op"))

	// setowner and purge act across API owners: admin only (4.6).
	setowner := tsigPost("setowner", K1, "")
	setowner.Owner = app2Owner
	_, o = s.app1.keystore(setowner)
	s.refused("6.10", "app1 tsig setowner", o, needsAdmin, s.tsigOwner(K1, app1Owner))
	n := s.tsigTotal()
	_, o = s.app1.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "purge", Force: true})
	s.refused("6.11", "app1 tsig purge", o, needsAdmin, s.tsigCount(n))

	ex, o := s.app1.keystore(tsigPost("export", K1, ""))
	s.expect("6.12", "app1 tsig export of its own "+K1, o.OK && ex.TsigExport != nil && ex.TsigExport.Secret == s.secrets[K1],
		orMsg("the secret it was added with", o), o.Msg)
	_, o = s.app1.keystore(tsigPost("export", KAP2, ""))
	s.refused("6.13", "app1 tsig export "+KAP2+" (app2's)", o, []string{"not found"})
	_, o = s.app1.keystore(tsigPost("delete", strings.ToUpper(KAP2), ""))
	s.refused("6.14", "app1 tsig delete "+strings.ToUpper(KAP2)+" (app2's, upper case)", o, []string{"not found"},
		s.tsigOwner(KAP2, app2Owner))

	_, o = s.app1.zone(tdns.ZonePost{Command: "add", Zone: Z9, Primaries: []tdns.PeerConf{{Addr: s.o.Primary, Key: KAP2}}})
	s.refused("6.15", "app1 zone add naming "+KAP2+" (app2's) for its primary", o,
		[]string{"is not a key of API owner cert:app1"}, s.zoneAbsent(Z9))

	// A new key is the caller's (4.6), whatever the request names, by every
	// way in: add, generate, import, bulk-import.
	k3 := tsigPost("add", K3, s.secret(K3))
	k3.Owner = app2Owner
	_, o = s.app1.keystore(k3)
	s.ok("6.16", "app1 tsig add "+K3+" naming owner cert:app2 in the request", o, s.tsigOwner(K3, app1Owner))
	_, o = s.app1.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "generate", TsigKeyname: K4, TsigAlgorithm: "hmac-sha256"})
	s.ok("6.17", "app1 tsig generate "+K4, o, s.tsigOwner(K4, app1Owner))

	data := bindKey(K5, s.secret(K5)) + bindKey(KOP, "aW1wb3J0IG92ZXIgb3AncyBrZXksIGFub3RoZXIgc2VjcmV0")
	ir, o := s.app1.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "import", TsigImportData: data, TsigImportFormat: "bind"})
	disp := map[string]string{}
	for _, d := range ir.TsigImport {
		disp[d.Name] = d.Status
	}
	bad := s.states([]state{s.tsigOwner(K5, app1Owner), s.tsigOwner(KOP, "cert:op"), s.tsigSecretKept(KOP)})
	s.expect("6.18", "app1 tsig import: its new "+K5+" in, "+KOP+" (op's) refused", disp[K5] == "imported" && disp[KOP] == "refused" && bad == "",
		fmt.Sprintf("dispositions %v; %s", disp, orNone(bad)), o.Msg)

	br, o := s.app1.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "bulk-import", BulkTsigKeys: []tdns.BulkTsigKey{
		{Keyname: K6, Algorithm: "hmac-sha256", Secret: s.secret(K6), Owner: app2Owner},
		{Keyname: KAP2, Algorithm: "hmac-sha256", Secret: "YnVsayBvdmVyIGFwcDIncyBrZXksIGFub3RoZXIgc2VjcmV0"},
	}})
	disp = map[string]string{}
	for _, d := range br.BulkDispositions {
		disp[d.Name] = d.Status
	}
	bad = s.states([]state{s.tsigOwner(K6, app1Owner), s.tsigOwner(KAP2, app2Owner), s.tsigSecretKept(KAP2)})
	s.expect("6.19", "app1 tsig bulk-import: its new "+K6+" in as its own, "+KAP2+" refused",
		disp[K6] == "imported" && disp[KAP2] == "refused" && bad == "",
		fmt.Sprintf("dispositions %v; %s", disp, orNone(bad)), o.Msg)

	s.inlineKeys()
}

// inlineKeys: Johan's ruling of 2026-11-24, "refuse an inline tsig key that
// someone else owns". An application's zone add or modify whose inline key
// exists under another API owner is refused, even when it is identical: the
// no-op would attach the key to the application's zone and then block its
// owner's delete ("in use"). The application's own key, given inline again,
// is fine.
func (s *suite) inlineKeys() {
	othersKey := []string{"exists and is not a key of API owner cert:app1"}
	_, o := s.app2.keystore(tsigPost("add", KSP2, s.secret(KSP2)))
	s.ok("6.20", "app2 tsig add "+KSP2+" (unused)", o, s.tsigOwner(KSP2, app2Owner))

	_, o = s.app1.zone(tdns.ZonePost{Command: "add", Zone: Z7, Primaries: s.secondary(), TsigName: KSP2, TsigSecret: s.secrets[KSP2]})
	s.refused("6.21", "app1 zone add "+Z7+" with app2's "+KSP2+" inline, identical secret", o, othersKey,
		s.zoneAbsent(Z7), s.tsigOwner(KSP2, app2Owner))
	z1Prim := s.o.Primary2 + "/" + K1 // as 3.1 left it
	_, o = s.app1.zone(tdns.ZonePost{Command: "modify", Zone: Z1, Primaries: []tdns.PeerConf{{Addr: s.o.Primary2, Key: tdns.NOKEY}},
		TsigName: KSP2, TsigSecret: s.secrets[KSP2]})
	s.refused("6.22", "app1 zone modify "+Z1+" with app2's "+KSP2+" inline, identical secret", o, othersKey,
		s.primariesAre(Z1, z1Prim), s.tsigOwner(KSP2, app2Owner))
	_, o = s.app2.keystore(tsigPost("delete", KSP2, ""))
	s.ok("6.23", "app2 tsig delete of its "+KSP2+": no zone of app1's holds it", o, s.tsigAbsent(KSP2))

	_, o = s.app1.zone(tdns.ZonePost{Command: "add", Zone: Z6, Primaries: s.secondary(), TsigName: K3, TsigSecret: s.secrets[K3]})
	s.ok("6.24", "app1 zone add "+Z6+" with its own "+K3+" inline, identical secret", o,
		s.zoneOwner(Z6, app1Owner), s.primariesAre(Z6, s.o.Primary+"/"+K3), s.tsigOwner(K3, app1Owner))
	_, o = s.app1.zone(tdns.ZonePost{Command: "modify", Zone: Z1, Primaries: []tdns.PeerConf{{Addr: s.o.Primary2, Key: tdns.NOKEY}},
		TsigName: K1, TsigSecret: s.secrets[K1]})
	s.ok("6.25", "app1 zone modify "+Z1+" with its own "+K1+" inline, identical secret", o,
		s.primariesAre(Z1, z1Prim), s.tsigOwner(K1, app1Owner))
	_, o = s.app1.zone(tdns.ZonePost{Command: "delete", Zone: Z6})
	s.ok("6.26", "app1 zone delete of its own "+Z6, o, s.zoneAbsent(Z6))
}

// 7. DNSSEC and SIG(0) keys (design 4.4, 4.6, decision 3, R9).
func (s *suite) check7Dnssec() {
	_, o := s.app1.zone(tdns.ZonePost{Command: "add", Zone: P1, ZoneType: "primary", Template: s.o.Template})
	s.ok("7.1", "app1 adds primary "+P1, o, s.zoneOwner(P1, app1Owner))

	_, o = s.app1.keystore(dnssecGenerate(P1))
	s.ok("7.2", "app1 dnssec generate for its own "+P1, o, s.dnssecCount(P1, 1))

	ks, o := s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "list"})
	mine := keyIDs(ks.Dnskeys)
	s.expect("7.3", "app1 dnssec list: its own zones' keys only", o.OK && sameSet(keys(mine), []string{P1}),
		fmt.Sprintf("keys of %s", list(keys(mine))), o.Msg)

	exported := -1
	if ids := mine[P1]; len(ids) == 1 {
		ex, o := s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "export", Zone: P1, Keyid: uint16(ids[0])})
		priv := ""
		for _, k := range ex.Dnskeys {
			priv = k.PrivateKey
		}
		if s.expect("7.4", "app1 dnssec export of its own "+P1+" key", o.OK && strings.Contains(priv, "PRIVATE KEY"),
			orMsg(fmt.Sprintf("keyid %d, private key of %d bytes", ids[0], len(priv)), o), o.Msg) {
			exported = ids[0]
		}
	} else {
		s.expect("7.4", "app1 dnssec export of its own "+P1+" key", false, fmt.Sprintf("no single key to export: %v", ids))
	}

	_, o = s.app1.keystore(sig0Generate(P1))
	s.ok("7.5", "app1 sig0 generate for its own "+P1, o, s.sig0Count(P1, 1))

	_, o = s.app1.keystore(dnssecGenerate(S2))
	s.refused("7.6", "app1 dnssec generate for "+S2+" (config's)", o, notOwnConfig, s.dnssecCount(S2, 0))
	_, o = s.app1.keystore(dnssecGenerate(P2))
	s.refused("7.7", "app1 dnssec generate for "+P2+" (app2's)", o, notOwnCert, s.dnssecCount(P2, 1))
	_, o = s.app1.keystore(sig0Generate(S2))
	s.refused("7.8", "app1 sig0 generate for "+S2+" (config's)", o, notOwnConfig, s.sig0Count(S2, 0))
	_, o = s.app1.keystore(dnssecGenerate(strings.ToUpper(P2)))
	s.refused("7.9", "app1 dnssec generate for "+strings.ToUpper(P2)+" (app2's, upper case)", o, notOwnCert,
		s.dnssecCount(P2, 1), s.dnssecCount(strings.ToUpper(P2), 0))

	all, err := s.au.dnssec()
	if err == nil && len(all[P2]) == 1 {
		// Answered as an export of a missing key of its own zone, so that
		// app1 cannot tell another owner's key from no key (C 344c6e0d).
		// The operator's log says what happened (C c85fa491).
		keyid := all[P2][0]
		_, o = s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "export", Zone: P2, Keyid: uint16(keyid)})
		s.refused("7.10", "app1 dnssec export of "+P2+"'s key (app2's): answered not found", o,
			[]string{fmt.Sprintf("DNSSEC key for zone %q keyid %d not found", P2, keyid)},
			s.loggedRefusal("dnssec", P2, keyid))
		_, o = s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "setstate", Keyname: P2, Zone: P2,
			Keyid: uint16(all[P2][0]), State: "retired"})
		s.refused("7.11", "app1 dnssec setstate of "+P2+"'s key (app2's)", o, notOwnCert, s.dnssecStateIs(P2, all[P2][0], "active"))
	} else {
		s.expect("7.10", "app1 dnssec export of "+P2+"'s key (app2's)", false, fmt.Sprintf("audit: %v %v", err, all[P2]))
	}

	own := []string{S1, C1, Z1, P1}
	bd, o := s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "bulk-export"})
	var zs []string
	for _, k := range bd.BulkDnssecKeys {
		zs = append(zs, k.Zone)
	}
	s.expect("7.12", "app1 dnssec bulk-export: its own zones' keys only",
		o.OK && sameSet(zs, []string{P1}) && len(intersect(zs, own)) == len(zs), fmt.Sprintf("keys of %s", list(zs)), o.Msg)
	bs, o := s.app1.keystore(tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "bulk-export"})
	zs = nil
	for _, k := range bs.BulkSig0Keys {
		zs = append(zs, k.Zone)
	}
	s.expect("7.13", "app1 sig0 bulk-export: its own zones' keys only",
		o.OK && sameSet(zs, []string{P1}) && len(intersect(zs, own)) == len(zs), fmt.Sprintf("keys of %s", list(zs)), o.Msg)
	bt, o := s.app1.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "bulk-export"})
	zs = nil
	for _, k := range bt.BulkTsigKeys {
		zs = append(zs, k.Keyname)
	}
	wantT := s.tsigOf(app1Owner)
	s.expect("7.14", "app1 tsig bulk-export: its own keys only", o.OK && sameSet(zs, wantT),
		fmt.Sprintf("keys %s; app1's by the audit: %s", list(sorted(zs)), list(wantT)), o.Msg)

	// clear, policy-cleanup and check act across API owners: admin only (4.6).
	_, o = s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "clear", Zone: P1})
	s.refused("7.15", "app1 dnssec clear of its own "+P1, o, needsAdmin, s.dnssecCount(P1, 1))
	_, o = s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "policy-cleanup", Zone: P1})
	s.refused("7.16", "app1 dnssec policy-cleanup of its own "+P1, o, needsAdmin, s.dnssecCount(P1, 1))
	_, o = s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "check", Zone: P1})
	s.refused("7.17", "app1 dnssec check", o, needsAdmin)
	// The truststore stays admin (design section 2). list-dnskey is a
	// truststore command in the code; see README.md, question Q1.
	_, o = s.app1.truststore(tdns.TruststorePost{Command: "list-dnskey"})
	s.refused("7.18", "app1 truststore list-dnskey", o, needsAdmin)
	_, o = s.app1.truststore(tdns.TruststorePost{Command: "child-sig0-mgmt", SubCommand: "list"})
	s.refused("7.19", "app1 truststore child-sig0-mgmt list", o, needsAdmin)

	// R9: every private-key export is logged with the client and key ID.
	want := fmt.Sprintf("private key exported client=app1 via=certificate app=true kind=dnssec zone=%s keyid=%d", P1, exported)
	logged, err := os.ReadFile(s.o.DaemonLog)
	s.expect("7.20", "the daemon logs app1's private-key export (R9)", err == nil && exported >= 0 && strings.Contains(string(logged), want),
		fmt.Sprintf("looked for %q in the daemon log", want))

	s.setstateNamesAnotherZone(exported)
}

// setstateNamesAnotherZone (R1: "a command acts on a zone other than the one
// checked"): dnssec-mgmt setstate is checked on Keyname, the key it changes.
// After the commit the handler republishes and re-signs the zone named in
// Zone. app1 changes its own P1 key (to the state it has) and names the
// config's signed zone in Zone; nothing may happen to that zone. The
// operator's own setstate on that zone is the control: it shows the re-sign
// in the daemon log.
func (s *suite) setstateNamesAnotherZone(p1key int) {
	const id = "7.21"
	name := "app1 dnssec setstate of its own " + P1 + " key, naming " + SIG + " in Zone"
	marker := "resigner: signatures replaced zone=" + SIG
	ids, err := s.au.dnssec()
	if err != nil || len(ids[SIG]) == 0 || p1key < 0 {
		s.expect(id, name, false, fmt.Sprintf("no keys to work with: %s has %v (%v), P1 key %d", SIG, ids[SIG], err, p1key))
		return
	}
	n0 := s.logCount(marker)
	out, cerr := s.adm.run("auth", "keystore", "dnssec", "setstate", "-z", SIG, "--keyid", fmt.Sprint(ids[SIG][0]), "--state", "active")
	if !waitFor(func() bool { return s.logCount(marker) > n0 }) {
		s.expect(id, name, false, "control: the operator's setstate on "+SIG+" logged no re-sign, so this check cannot see one",
			cmdOutcome(out, cerr).Msg)
		return
	}
	n1 := s.logCount(marker)
	_, o := s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "setstate", Keyname: P1, Zone: SIG,
		Keyid: uint16(p1key), State: "active"})
	waitFor(func() bool { return s.logCount(marker) > n1 })
	n2 := s.logCount(marker)
	s.expect(id, name+": no action on "+SIG, n2 == n1,
		fmt.Sprintf("request %s; %q in the daemon log: %d after the operator's control, %d after app1's request",
			orMsg("accepted", o), marker, n1, n2))
}

// loggedRefusal: the daemon logged, for the operator, app1's refused
// export of a key of the given kind, zone and key ID (design R9; C
// c85fa491).
func (s *suite) loggedRefusal(kind, zone string, keyid int) state {
	parts := []string{"private key export refused", "client=app1", "kind=" + kind, "zone=" + zone, fmt.Sprintf("keyid=%d", keyid)}
	return func() string {
		if waitFor(func() bool { return s.logLineWith(parts...) }) {
			return ""
		}
		return "no line in the daemon log with " + strings.Join(parts, ", ")
	}
}

// logLineWith: one line of the daemon log contains every part.
func (s *suite) logLineWith(parts ...string) bool {
	b, err := os.ReadFile(s.o.DaemonLog)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		all := true
		for _, p := range parts {
			if !strings.Contains(l, p) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// logCount is how many lines of the daemon log contain s.
func (s *suite) logCount(sub string) int {
	b, err := os.ReadFile(s.o.DaemonLog)
	if err != nil {
		return -1
	}
	return strings.Count(string(b), sub)
}

// 8. zone delete deletes the zone's keys (design 4.10, decisions 4 and 7).
func (s *suite) check8DeleteAndKeys() {
	_, o := s.app1.zone(tdns.ZonePost{Command: "delete", Zone: P1, KeepKeys: true})
	s.refused("8.1", "app1 zone delete "+P1+" --keep-keys", o, []string{"--keep-keys: not available to application clients"},
		s.zoneOwner(P1, app1Owner), s.dnssecCount(P1, 1), s.sig0Count(P1, 1))

	resp, o := s.app1.zone(tdns.ZonePost{Command: "delete", Zone: P1})
	s.ok("8.2", "app1 zone delete "+P1+" deletes its DNSSEC and SIG(0) keys", o,
		s.zoneAbsent(P1), s.dnssecCount(P1, 0), s.sig0Count(P1, 0),
		func() string {
			r := resp.Removal
			if r == nil || r.DnssecKeys != 1 || r.Sig0Keys != 1 {
				return fmt.Sprintf("the reply's removal is %+v, expected 1 DNSSEC and 1 SIG(0) key", r)
			}
			return ""
		})

	// P3: keys kept by the operator.
	_, o = s.app1.zone(tdns.ZonePost{Command: "add", Zone: P3, ZoneType: "primary", Template: s.o.Template})
	if s.ok("8.3", "app1 adds primary "+P3, o, s.zoneOwner(P3, app1Owner)) {
		_, o1 := s.app1.keystore(dnssecGenerate(P3))
		_, o2 := s.app1.keystore(sig0Generate(P3))
		s.ok("8.4", "app1 generates a DNSSEC and a SIG(0) key for "+P3, both(o1, o2), s.dnssecCount(P3, 1), s.sig0Count(P3, 1))
	}
	dk, _ := s.au.dnssec()
	sk, _ := s.au.sig0()
	keptD, keptS := dk[P3], sk[P3]

	out, err := s.adm.run("auth", "zone", "delete", "-z", P3, "--keep-keys")
	s.ok("8.5", "the operator deletes "+P3+" --keep-keys over the socket", cmdOutcome(out, err),
		s.zoneAbsent(P3), s.dnssecIDs(P3, keptD), s.sig0IDs(P3, keptS))

	_, o = s.app1.zone(tdns.ZonePost{Command: "add", Zone: P3, ZoneType: "primary", Template: s.o.Template})
	s.refused("8.6", "app1 re-adds "+P3+" while its kept keys remain", o, []string{"key(s) of an earlier zone remain"},
		s.zoneAbsent(P3), s.dnssecIDs(P3, keptD), s.sig0IDs(P3, keptS))

	out, err = s.adm.run("auth", "zone", "add", "-z", P3, "--type", "primary", "--template", s.o.Template)
	s.ok("8.7", "the operator re-adds "+P3+" over the socket and takes the kept keys", cmdOutcome(out, err),
		s.zoneOwner(P3, "api"), s.dnssecIDs(P3, keptD), s.sig0IDs(P3, keptS))

	ks, o := s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "list"})
	s.expect("8.8", "app1 does not see "+P3+"'s keys while it is api's", o.OK && len(keyIDs(ks.Dnskeys)[P3]) == 0,
		fmt.Sprintf("app1 sees keys of %s", list(keys(keyIDs(ks.Dnskeys)))), o.Msg)

	out, err = s.adm.run("auth", "zone", "setowner", P3, app1Owner)
	s.ok("8.9", "the operator hands "+P3+" to app1 (zone setowner)", cmdOutcome(out, err), s.zoneOwner(P3, app1Owner))
	ks, o = s.app1.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "list"})
	s.expect("8.10", "app1 now sees "+P3+"'s kept keys", o.OK && len(keptD) > 0 && slices.Equal(keyIDs(ks.Dnskeys)[P3], keptD),
		fmt.Sprintf("app1 sees %v of %s, kept %v", keyIDs(ks.Dnskeys)[P3], P3, keptD), o.Msg)

	// A provisioning application that rolls an add back at once: the
	// delete must leave no zone behind (4.10), while the zone is still
	// loading as well as after.
	_, o = s.app1.zone(tdns.ZonePost{Command: "add", Zone: P4, ZoneType: "primary", Template: s.o.Template})
	if s.ok("8.11", "app1 adds primary "+P4, o) {
		_, o = s.app1.zone(tdns.ZonePost{Command: "delete", Zone: P4})
		time.Sleep(time.Second)
		s.ok("8.12", "app1 deletes "+P4+" right after the add: a second later it is gone", o, s.zoneAbsent(P4),
			func() string {
				if q := s.query(P4, dns.TypeSOA); !strings.HasPrefix(q, "REFUSED") {
					return "DNS " + P4 + " SOA answers " + q + ", not REFUSED"
				}
				return ""
			})
		// Whatever 8.12 found, P4 must not be there for the checks after.
		if _, ok, _ := s.au.owner(P4); ok {
			s.app1.zone(tdns.ZonePost{Command: "delete", Zone: P4})
		}
	}
}

// 9. Isolation and handover (design 4.5, 4.8).
func (s *suite) check9Isolation() {
	app1Zones := []string{S1, C1, Z1, P3}
	resp, o := s.app2.zone(tdns.ZonePost{Command: "list-zones"})
	got := keys(resp.Zones)
	s.expect("9.1", "app2 list-zones shows none of app1's zones", o.OK && sameSet(got, []string{Z2, P2}),
		fmt.Sprintf("app2 sees %s; of app1's: %s", list(got), list(intersect(got, app1Zones))), o.Msg)

	ks, o := s.app2.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "list"})
	var names []string
	for _, k := range ks.TsigKeys {
		names = append(names, k.Name)
	}
	s.expect("9.2", "app2 tsig list shows none of app1's keys", o.OK && sameSet(names, []string{KAP2}),
		fmt.Sprintf("app2 sees %s", list(names)), o.Msg)

	ks, o = s.app2.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "list"})
	got = keys(keyIDs(ks.Dnskeys))
	s.expect("9.3", "app2 dnssec list shows none of app1's keys", o.OK && sameSet(got, []string{P2}),
		fmt.Sprintf("app2 sees keys of %s", list(got)), o.Msg)

	_, o = s.app2.zone(tdns.ZonePost{Command: "get-name", Zone: S1, UpdateName: "www." + S1})
	s.refused("9.4", "app2 get-name in "+S1+" (app1's)", o, []string{"not a zone of API owner cert:app2"})

	out, err := s.adm.run("auth", "zone", "setowner", Z1, app2Owner)
	s.ok("9.5", "the operator hands "+Z1+" to app2 (zone setowner)", cmdOutcome(out, err), s.zoneOwner(Z1, app2Owner))

	np := []tdns.PeerConf{{Addr: s.o.Primary, Key: tdns.NOKEY}}
	_, o = s.app2.zone(tdns.ZonePost{Command: "modify", Zone: Z1, Primaries: np})
	s.ok("9.6", "app2 zone modify "+Z1+" after the handover", o, s.primariesAre(Z1, s.o.Primary+"/"+tdns.NOKEY))
	_, o = s.app1.zone(tdns.ZonePost{Command: "modify", Zone: Z1, Primaries: []tdns.PeerConf{{Addr: s.o.Primary2, Key: tdns.NOKEY}}})
	s.refused("9.7", "app1 zone modify "+Z1+" after the handover", o, notOwnCert, s.primariesAre(Z1, s.o.Primary+"/"+tdns.NOKEY))
	_, o = s.app1.zone(tdns.ZonePost{Command: "delete", Zone: Z1})
	s.refused("9.8", "app1 zone delete "+Z1+" after the handover", o, notOwnCert, s.zoneOwner(Z1, app2Owner))

	r1, o1 := s.app1.zone(tdns.ZonePost{Command: "list-zones"})
	r2, o2 := s.app2.zone(tdns.ZonePost{Command: "list-zones"})
	_, in1 := r1.Zones[Z1]
	_, in2 := r2.Zones[Z1]
	s.expect("9.9", Z1+" moved from app1's list to app2's", o1.OK && o2.OK && !in1 && in2,
		fmt.Sprintf("in app1's list: %v, in app2's: %v", in1, in2), o1.Msg, o2.Msg)

	// Z1 no longer uses K1, so app1 may clean it up.
	_, o = s.app1.keystore(tsigPost("delete", K1, ""))
	s.ok("9.10", "app1 tsig delete "+K1+", unused since app2's modify", o, s.tsigAbsent(K1))

	// Z1, now app2's, is still a member of app1's catalog C1 (4.1, 4.10).
	// Johan's ruling of 2026-11-24, "catalog owner may remove any member":
	// zone-delete and zone-group-delete need only the catalog zone, and the
	// member zone itself stays. Adding a member still needs both.
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "zone-group-delete", CatalogZone: C1, Zone: Z1, Group: GRP})
	s.ok("9.11", "app1 catalog zone-group-delete "+GRP+" of "+Z1+" (now app2's) in its own "+C1, o,
		s.memberGroup(C1, Z1, GRP, false), s.member(C1, Z1, true))
	_, o = s.app2.catalog(tdns.CatalogPost{Command: "zone-delete", CatalogZone: C1, Zone: Z1})
	s.refused("9.12", "app2 catalog zone-delete of its "+Z1+" from "+C1+" (app1's)", o,
		[]string{"not a zone of API owner cert:app2"}, s.member(C1, Z1, true))
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "zone-delete", CatalogZone: C1, Zone: Z1})
	s.ok("9.13", "app1 catalog zone-delete of "+Z1+" (now app2's) from its own "+C1+"; the zone stays", o,
		s.member(C1, Z1, false), s.zoneOwner(Z1, app2Owner))
	_, o = s.app1.catalog(tdns.CatalogPost{Command: "zone-add", CatalogZone: C1, Zone: Z1})
	s.refused("9.14", "app1 catalog zone-add of "+Z1+" (app2's) back into its own "+C1, o, notOwnCert, s.member(C1, Z1, false))
}

// 10. The operator's certificate stays unscoped (design 4.8).
func (s *suite) check10Operator() {
	all := []string{S1, S2, SIG, C1, C2, Z1, Z2, P2, P3, AO1, OZ1}
	resp, o := s.op.zone(tdns.ZonePost{Command: "list-zones"})
	got := keys(resp.Zones)
	s.expect("10.1", "op list-zones shows every zone", o.OK && sameSet(got, all),
		fmt.Sprintf("op sees %s", list(got)), o.Msg)

	_, o = s.op.zone(tdns.ZonePost{Command: "update", Zone: S2, UpdateVerb: "addrr", UpdateRRs: []string{"op." + S2 + " 300 IN A 192.0.2.80"}})
	s.ok("10.2", "op zone update in "+S2+" (config's)", o, s.publishes(S2, "op."+S2, "A", "192.0.2.80"))
	_, o = s.op.zone(tdns.ZonePost{Command: "update", Zone: S1, UpdateVerb: "addrr", UpdateRRs: []string{"op." + S1 + " 300 IN A 192.0.2.81"}})
	s.ok("10.3", "op zone update in "+S1+" (granted to app1)", o, s.publishes(S1, "op."+S1, "A", "192.0.2.81"))
	_, o = s.op.zone(tdns.ZonePost{Command: "modify", Zone: Z2, Primaries: []tdns.PeerConf{{Addr: s.o.Primary2, Key: KAP2}}})
	s.ok("10.4", "op zone modify "+Z2+" (app2's)", o, s.primariesAre(Z2, s.o.Primary2+"/"+KAP2))
	_, o = s.op.zone(tdns.ZonePost{Command: "modify", Zone: AO1, Primaries: []tdns.PeerConf{{Addr: s.o.Primary2, Key: tdns.NOKEY}}})
	s.ok("10.5", "op zone modify "+AO1+" (api's)", o, s.primariesAre(AO1, s.o.Primary2+"/"+tdns.NOKEY))
	_, o = s.op.zone(tdns.ZonePost{Command: "get-name", Zone: P2, UpdateName: P2})
	s.ok("10.6", "op get-name in "+P2+" (app2's)", o)

	_, o = s.op.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "list"})
	s.refused("10.7", "op keystore tsig list over TCP", o, needsAdmin)
	_, o = s.op.keystore(tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "list"})
	s.refused("10.8", "op keystore dnssec list over TCP", o, needsAdmin)

	// Status shows the application clients (4.8).
	cr, o := s.op.config(tdns.ConfigPost{Command: "status"})
	var apps []string
	if cr.Access != nil {
		apps = cr.Access.AppClients
	}
	s.expect("10.9", "op config status shows the app-clients", o.OK && sameSet(apps, []string{"app1", "app2"}),
		orMsg("app-clients "+list(apps), o), o.Msg)
}

// 11. The API key (design 4.9, R5).
func (s *suite) check11ApiKey() {
	const warn = "the key bypasses every application limit"
	out, err := s.adm.run("auth", "config", "check", "--serverconfig", s.o.DaemonConfig)
	s.expect("11.1", "config check warns: app-clients set, keyauth on", strings.Contains(out, warn),
		fmt.Sprintf("found %q (exit: %v)", warn, err), out)

	resp, o := s.key.ping()
	s.expect("11.2", "a key caller is read-write, and no application", o.OK && strings.Contains(resp.Auth, "by api key") &&
		!strings.Contains(resp.Auth, "application client"), fmt.Sprintf("ping: %s", orMsg(resp.Auth, o)))

	zr, o := s.key.zone(tdns.ZonePost{Command: "list-zones"})
	got := keys(zr.Zones)
	s.expect("11.3", "a key caller sees app1's and app2's zones", o.OK && len(intersect(got, []string{S1, Z1, Z2, P2, P3})) == 5,
		fmt.Sprintf("sees %s", list(got)), o.Msg)
	_, o = s.key.zone(tdns.ZonePost{Command: "modify", Zone: Z2, Primaries: []tdns.PeerConf{{Addr: s.o.Primary, Key: KAP2}}})
	s.ok("11.4", "a key caller modifies "+Z2+" (app2's)", o, s.primariesAre(Z2, s.o.Primary+"/"+KAP2))
	_, o = s.key.zone(tdns.ZonePost{Command: "add", Zone: KZ, Primaries: s.secondary()})
	s.ok("11.5", "a key caller's zone add records API owner api", o, s.zoneOwner(KZ, "api"))
	_, o = s.key.keystore(tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "list"})
	s.refused("11.6", "a key caller's keystore tsig list", o, needsAdmin)

	out, err = s.adm.run("auth", "client", "keyauth", "off")
	s.ok("11.7", "the operator turns keyauth off (tdns-ncli)", cmdOutcome(out, err))
	out, err = s.adm.run("auth", "config", "check", "--serverconfig", s.o.DaemonConfig)
	s.expect("11.8", "config check no longer warns about the key", err == nil && !strings.Contains(out, warn) &&
		strings.Contains(out, "API access file"), fmt.Sprintf("no %q (exit: %v)", warn, err), out)
	_, o = s.key.ping()
	s.refused("11.9", "a key caller with keyauth off", o, []string{"Forbidden"})
}

// notesDesignSilent: cases the design does not decide. What the daemon did
// is printed, not judged (README.md, questions).
func (s *suite) notesDesignSilent() {
	// Q2: a zone inside another API owner's zone. Johan, 2026-11-24: nested
	// zones with another owner are allowed. Still open: one that the parent
	// does not delegate (no NS at the cut), as here. The operator's record
	// below the new zone's apex, asked over DNS before, while and after
	// app1's zone is there.
	name := "www." + SUB
	_, o := s.op.zone(tdns.ZonePost{Command: "update", Zone: S2, UpdateVerb: "addrr", UpdateRRs: []string{name + " 300 IN A 192.0.2.99"}})
	if !o.OK {
		s.note("Q2", "could not put "+name+" into "+S2+": "+firstLine(o.Msg))
		return
	}
	before := s.query(name, dns.TypeA)
	_, o = s.app1.zone(tdns.ZonePost{Command: "add", Zone: SUB, ZoneType: "primary", Template: s.o.Template})
	if !o.OK {
		s.note("Q2", fmt.Sprintf("app1 zone add of primary %s (inside the config's %s) was refused: %s", SUB, S2, firstLine(o.Msg)))
		return
	}
	// It loads from its bootstrap file in the background; wait for its
	// SOA, so that a delete does not race the load (check 8.12).
	waitFor(func() bool { return strings.HasPrefix(s.query(SUB, dns.TypeSOA), "NOERROR") })
	during := s.query(name, dns.TypeA)
	owner, _, _ := s.au.owner(SUB)
	s.app1.zone(tdns.ZonePost{Command: "delete", Zone: SUB})
	waitFor(func() bool { return s.query(name, dns.TypeA) == before })
	after := s.query(name, dns.TypeA)
	s.note("Q2", fmt.Sprintf("app1 zone add of primary %s (inside the config's %s, which has no NS at the cut): "+
		"ACCEPTED, API owner %s. DNS %s A: before %q; with app1's zone %q; after app1 deleted it %q",
		SUB, S2, owner, name, before, during, after))
}

// waitFor polls cond for up to five seconds.
func waitFor(cond func() bool) bool {
	for range 20 {
		if cond() {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

// ---- requests ---------------------------------------------------------------

func dnssecGenerate(zone string) tdns.KeystorePost {
	return tdns.KeystorePost{Command: "dnssec-mgmt", SubCommand: "generate", Zone: zone,
		KeyType: "ZSK", State: "active", Algorithm: dns.ED25519}
}

func sig0Generate(zone string) tdns.KeystorePost {
	return tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: zone, Keyname: zone,
		State: "active", Algorithm: dns.ED25519}
}

func tsigPost(sub, name, secret string) tdns.KeystorePost {
	kp := tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: sub, TsigKeyname: name}
	if secret != "" {
		kp.TsigAlgorithm = "hmac-sha256"
		kp.TsigSecret = secret
	}
	return kp
}

// bindKey is a TSIG key as a BIND config has it, for tsig-mgmt import.
func bindKey(name, secret string) string {
	return fmt.Sprintf("key %q {\n\talgorithm hmac-sha256;\n\tsecret %q;\n};\n", name, secret)
}

// tsigTotal is how many TSIG keys the keystore holds now, -1 if unknown.
func (s *suite) tsigTotal() int {
	k, err := s.au.tsig()
	if err != nil {
		return -1
	}
	return len(k)
}

// leakedSecrets is the names of the suite's TSIG keys whose secret is in raw.
func (s *suite) leakedSecrets(raw []byte) []string {
	var out []string
	for name, sec := range s.secrets {
		if sec != "" && strings.Contains(string(raw), sec) {
			out = append(out, name)
		}
	}
	return out
}

// cmdOutcome is a tdns-ncli run as an outcome: it worked if it exited 0 and
// printed no error.
func cmdOutcome(out string, err error) outcome {
	low := strings.ToLower(out)
	if err != nil || strings.HasPrefix(strings.TrimSpace(low), "error") || strings.Contains(low, "refused by") {
		msg := out
		if err != nil {
			msg = fmt.Sprintf("%s(exit: %v)", out, err)
		}
		return outcome{Msg: msg}
	}
	return outcome{OK: true, Msg: out}
}

// both is the outcome of two requests that must both work.
func both(a, b outcome) outcome {
	if !a.OK {
		return a
	}
	if !b.OK {
		return b
	}
	return outcome{OK: true, HTTP: b.HTTP, Msg: firstLine(a.Msg) + "; " + firstLine(b.Msg)}
}

// orMsg is v when o worked, else the daemon's error.
func orMsg(v string, o outcome) string {
	if o.OK {
		return v
	}
	return fmt.Sprintf("refused (HTTP %d): %s", o.HTTP, firstLine(o.Msg))
}

func orNone(bad string) string {
	if bad == "" {
		return "audit as expected"
	}
	return bad
}
