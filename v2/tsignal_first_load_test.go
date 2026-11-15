/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// signalPolicyValidity is the signature lifetime of the policy in the test
// below: long enough that a signature made under it cannot be mistaken for
// one with the five-minute no-policy lifetime (sigLifetime).
const signalPolicyValidity = 7 * 86400

// checkSignalSignedUnderPolicy reports an error unless zd serves a signed
// _dns.ns1.<zone> SVCB whose every signature has the policy's lifetime.
func checkSignalSignedUnderPolicy(t *testing.T, run string, zd *ZoneData) {
	t.Helper()
	owner := "_dns.ns1." + zd.ZoneName
	zd.mu.Lock()
	bound := zd.DnssecPolicy != nil
	zd.mu.Unlock()
	if !bound {
		t.Errorf("%s: zone %s: its DNSSEC policy did not bind", run, zd.ZoneName)
		return
	}
	od := getOwnerFrom(zd.publishedSnapshot(), owner)
	if od == nil || len(od.RRtypes.GetOnlyRRSet(dns.TypeSVCB).RRs) == 0 {
		t.Errorf("%s: zone %s serves no %s SVCB: its transport signal pass ran before its DNSSEC policy bound and was not run again",
			run, zd.ZoneName, owner)
		return
	}
	sigs := od.RRtypes.GetOnlyRRSet(dns.TypeSVCB).RRSIGs
	if len(sigs) == 0 {
		t.Errorf("%s: %s SVCB is not signed", run, owner)
		return
	}
	for _, rr := range sigs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if left := time.Until(time.Unix(int64(sig.Expiration), 0)); left < time.Hour {
			t.Errorf("%s: %s SVCB is signed with %v left, want the policy's %v: it was signed before the policy bound",
				run, owner, left.Round(time.Second), time.Duration(signalPolicyValidity)*time.Second)
		}
	}
}

// A signing zone gets its transport signal, signed under its DNSSEC policy, on
// a first start with an empty keystore and on every restart after it (#1058).
//
// The pass used to run when the last configured zone finished its first load,
// which is before that zone's policy binds. On a first start the zone had no
// keys, the pass failed for want of a policy, and nothing ran it again: the
// zone served no signal until a restart. On a restart the keys exist, so the
// pass signed, but with no policy bound: the five-minute no-policy lifetime.
// From an unsigned zone file the sign that follows the bind replaced that
// signature as near expiry. From a file that already carries signatures,
// which is what a zone write leaves, that sign does not run, and the short
// signature was what the zone served.
//
// Only the zone that finishes its first load last was hit, and with one zone
// that zone is always last; with two, the first one was fine.
func TestTheTransportSignalIsDerivedAfterThePolicyBinds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		zones []string
	}{
		{"one zone", []string{"one.tsig1058.example."}},
		{"two zones", []string{"one.tsig1058.example.", "two.tsig1058.example."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authApp(t)
			kdb := Conf.Internal.KeyDB
			pol := kskzsk(dns.ED25519, dns.ED25519)
			pol.SigValidity = PolicySigValidity{Default: signalPolicyValidity, DNSKEY: signalPolicyValidity, DS: signalPolicyValidity}
			withLivePolicies(t, map[string]DnssecPolicy{"base": pol})

			prevSVCB, prevListeners := Globals.ServerSVCB, Conf.Listeners.Addresses
			Globals.ServerSVCB = &dns.SVCB{Hdr: dns.RR_Header{Name: "_dns.server.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300}, Priority: 1, Target: "."}
			Conf.Listeners.Addresses = []string{"127.0.0.1:53"}
			t.Cleanup(func() { Globals.ServerSVCB, Conf.Listeners.Addresses = prevSVCB, prevListeners })

			dir := t.TempDir()
			files := map[string]string{}
			for _, z := range tc.zones {
				f := filepath.Join(dir, z+"zone")
				body := z + "\t3600\tIN\tSOA\tns1." + z + " hostmaster." + z + " 1 7200 1800 604800 7200\n" +
					z + "\t3600\tIN\tNS\tns1." + z + "\n" +
					"ns1." + z + "\t3600\tIN\tA\t127.0.0.1\n"
				if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
				files[z] = f
			}

			// One keystore throughout: empty on the first start, holding the
			// keys the first start minted on each restart. Before the last
			// restart each zone is written out to its file, signed, as a
			// `zone write` leaves it.
			runs := []struct {
				name      string
				writeOut  bool // write the zones to their files after this run
				signedRun bool
			}{
				{name: "first start"},
				{name: "restart", writeOut: true},
				{name: "restart from a signed zone file", signedRun: true},
			}
			for _, run := range runs {
				if run.signedRun {
					for _, z := range tc.zones {
						if text, err := os.ReadFile(files[z]); err != nil || !strings.Contains(string(text), "RRSIG") {
							t.Fatalf("%s: zone %s: precondition: its file carries no signatures (err %v)", run.name, z, err)
						}
					}
				}
				conf := &Config{}
				conf.Internal.KeyDB = kdb
				conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, len(tc.zones))
				conf.Internal.BumpZoneCh = make(chan BumperData, 1)
				conf.Internal.AllZones = tc.zones
				conf.Service.Transport.Type = "svcb"
				conf.Service.Transport.Signal = "do53:0,dot:40,doq:40,doh:20"
				conf.Listeners.Addresses = []string{"127.0.0.1:53"}

				// pre-registered, the way ParseZones leaves each zone before
				// its first load
				var zds []*ZoneData
				for _, z := range tc.zones {
					zd := &ZoneData{ZoneName: z, Logger: discardLogger(), FirstZoneLoad: true}
					zd.registerStandardRefreshHooks(conf.Internal.DelegationSyncQ)
					Zones.Set(z, zd)
					zds = append(zds, zd)
				}
				t.Cleanup(func() {
					for _, zd := range zds {
						zd.stopPublisher()
						Zones.Remove(zd.ZoneName)
					}
				})

				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() { defer close(done); RefreshEngine(ctx, conf) }()
				stop := func() {
					cancel()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("RefreshEngine did not shut down")
					}
				}
				t.Cleanup(stop)

				// The engine answers a config-bearing refresher of a zone's
				// first load when that load is complete, policy bind included.
				var resps []chan RefresherResponse
				for _, z := range tc.zones {
					resp := make(chan RefresherResponse, 1)
					resps = append(resps, resp)
					conf.Internal.RefreshZoneCh <- ZoneRefresher{
						Name:         z,
						ZoneType:     Primary,
						ZoneStore:    MapZone,
						Zonefile:     files[z],
						Options:      map[ZoneOption]bool{OptOnlineSigning: true, OptAddTransportSignal: true},
						DnssecPolicy: "base",
						ConfigUpdate: true,
						Response:     resp,
					}
				}
				for i, resp := range resps {
					select {
					case r := <-resp:
						if r.Error {
							t.Fatalf("%s: zone %s: first load failed: %s", run.name, tc.zones[i], r.ErrorMsg)
						}
					case <-time.After(10 * time.Second):
						t.Fatalf("%s: zone %s: the first load did not complete", run.name, tc.zones[i])
					}
				}
				for _, zd := range zds {
					checkSignalSignedUnderPolicy(t, run.name, zd)
				}

				stop()
				for _, zd := range zds {
					if run.writeOut {
						if _, err := zd.WriteZone(true, true); err != nil {
							t.Fatalf("%s: zone %s: WriteZone: %v", run.name, zd.ZoneName, err)
						}
					}
					zd.stopPublisher()
					Zones.Remove(zd.ZoneName)
				}
			}
		})
	}
}
