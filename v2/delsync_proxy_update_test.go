package tdns

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// U-a: the UPDATE-proxy precondition + KEY-bootstrap state machine (§10.8).
// The DSYNC-discovery gate is network and is exercised on the testbed; here we
// unit-test the post-gate logic: apex-KEY detection, ours-vs-foreign matching,
// keygen idempotency, and the operator-instruction text.

const proxyUpdZone = "upd.example."

func proxyUpdZoneData(t *testing.T, kdb *KeyDB, zoneStr string) *ZoneData {
	t.Helper()
	zd := testZone(t, proxyUpdZone, zoneStr)
	zd.KeyDB = kdb
	return zd
}

// genProxySig0Key generates an active SIG(0) key for the zone and returns its
// published KEY RR (as it would appear at the apex).
func genProxySig0Key(t *testing.T, kdb *KeyDB, zone string) *dns.KEY {
	t.Helper()
	if err := kdb.ensureSig0KeyForTest(zone); err != nil {
		t.Fatalf("generate SIG(0) key: %v", err)
	}
	sak, err := kdb.GetSig0Keys(zone, Sig0StateActive)
	if err != nil || sak == nil || len(sak.Keys) == 0 {
		t.Fatalf("GetSig0Keys after generate: %v (keys=%v)", err, sak)
	}
	k := sak.Keys[0].KeyRR
	k.Hdr.Name = zone
	return &k
}

// ensureSig0KeyForTest is a thin wrapper around the keygen path the proxy uses.
func (kdb *KeyDB) ensureSig0KeyForTest(zone string) error {
	kp := KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "generate",
		Zone:       zone,
		Keyname:    zone,
		Algorithm:  dns.ED25519,
		State:      Sig0StateActive,
		Creator:    "test",
	}
	_, err := kdb.Sig0KeyMgmt(nil, kp)
	return err
}

// No KEY at apex + no key in keystore: proxyEnsureSig0Key generates one and is
// idempotent (a second call does not generate a second key).
func TestProxyEnsureSig0KeyGeneratesAndIsIdempotent(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := proxyUpdZoneData(t, kdb, proxyUpdBaseZone())

	if err := zd.proxyEnsureSig0Key(kdb); err != nil {
		t.Fatalf("first proxyEnsureSig0Key: %v", err)
	}
	sak, _ := kdb.GetSig0Keys(proxyUpdZone, Sig0StateActive)
	if sak == nil || len(sak.Keys) != 1 {
		t.Fatalf("after first ensure: want 1 active SIG(0) key, got %v", sak)
	}
	if err := zd.proxyEnsureSig0Key(kdb); err != nil {
		t.Fatalf("second proxyEnsureSig0Key: %v", err)
	}
	sak, err := kdb.GetSig0Keys(proxyUpdZone, Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys after second ensure: %v", err)
	}
	if sak == nil {
		t.Fatalf("after second ensure: still want exactly 1 key (idempotent), got nil")
	}
	if len(sak.Keys) != 1 {
		t.Fatalf("after second ensure: still want exactly 1 key (idempotent), got %d", len(sak.Keys))
	}
}

// proxyHoldsPrivateKeyFor: true when an apex KEY matches a held key, false for a
// foreign KEY.
func TestProxyHoldsPrivateKeyFor(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := proxyUpdZoneData(t, kdb, proxyUpdBaseZone())
	ourKey := genProxySig0Key(t, kdb, proxyUpdZone)

	if !zd.proxyHoldsPrivateKeyFor(kdb, []dns.RR{ourKey}) {
		t.Fatal("should hold the private key for our own generated KEY")
	}

	// A foreign KEY (different key material → different keytag), parsed from
	// zone-file text.
	foreignRR, err := dns.NewRR(proxyUpdZone + " 3600 IN KEY 257 3 15 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatalf("parse foreign KEY: %v", err)
	}
	if zd.proxyHoldsPrivateKeyFor(kdb, []dns.RR{foreignRR}) {
		t.Fatal("must NOT claim to hold the private key for a foreign KEY")
	}
}

// proxyApexKEYs reads the apex KEY RRset.
func TestProxyApexKEYs(t *testing.T) {
	kdb := newTestKeyDB(t)
	// No KEY at apex.
	zdNoKey := proxyUpdZoneData(t, kdb, proxyUpdBaseZone())
	if got := zdNoKey.proxyApexKEYs(); len(got) != 0 {
		t.Fatalf("no-KEY zone should return no apex KEYs, got %d", len(got))
	}
	// KEY at apex.
	ourKey := genProxySig0Key(t, kdb, proxyUpdZone)
	zdKey := proxyUpdZoneData(t, kdb, proxyUpdBaseZone()+ourKey.String()+"\n")
	if got := zdKey.proxyApexKEYs(); len(got) != 1 {
		t.Fatalf("zone with a KEY should return 1 apex KEY, got %d", len(got))
	}
}

// The operator instruction is two records: the KEY RR and an HSYNCPARAM pubkey.
func TestProxyBootstrapInstruction(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := proxyUpdZoneData(t, kdb, proxyUpdBaseZone())
	if err := zd.proxyEnsureSig0Key(kdb); err != nil {
		t.Fatalf("ensure key: %v", err)
	}
	instr, err := zd.proxyBootstrapInstruction(kdb)
	if err != nil {
		t.Fatalf("proxyBootstrapInstruction: %v", err)
	}
	if !strings.Contains(instr, "\tKEY\t") && !strings.Contains(instr, " KEY ") {
		t.Fatalf("instruction missing a KEY record:\n%s", instr)
	}
	if !strings.Contains(instr, "HSYNCPARAM") || !strings.Contains(instr, "pubkey") {
		t.Fatalf("instruction missing HSYNCPARAM pubkey:\n%s", instr)
	}
	// Both records name the zone apex.
	for _, line := range strings.Split(strings.TrimSpace(instr), "\n") {
		if !strings.HasPrefix(line, proxyUpdZone) {
			t.Fatalf("instruction line not at apex: %q", line)
		}
	}
}

// The HSYNCPARAM pubkey record renders with the pubkey flag.
func TestProxyHsyncparamPubkeyRR(t *testing.T) {
	zd := &ZoneData{ZoneName: proxyUpdZone}
	rr := zd.proxyHsyncparamPubkeyRR()
	if !strings.Contains(rr, "HSYNCPARAM") || !strings.Contains(rr, "pubkey") {
		t.Fatalf("HSYNCPARAM pubkey RR malformed: %q", rr)
	}
	if !strings.HasPrefix(rr, proxyUpdZone) {
		t.Fatalf("HSYNCPARAM RR not at apex: %q", rr)
	}
}

func proxyUpdBaseZone() string {
	return `upd.example.	3600 IN SOA ns1.upd.example. hostmaster.upd.example. 1 7200 1800 604800 3600
upd.example.	3600 IN NS ns1.upd.example.
ns1.upd.example.	3600 IN A 192.0.2.1
`
}

// U-d: proxyUpdateMode defaults to replace and honors the parent-update option.
func TestProxyUpdateModeDefaultAndOverride(t *testing.T) {
	kdb := newTestKeyDB(t)

	// No option set ⇒ replace (the proxy default; differs from the auth-side
	// delta default).
	if got := proxyUpdateMode(kdb); got != UpdateModeReplace {
		t.Fatalf("default proxy update mode = %q, want replace", got)
	}

	// Operator chooses delta.
	kdb.SetOptions(map[AuthOption]string{AuthOptParentUpdate: UpdateModeDelta})
	if got := proxyUpdateMode(kdb); got != UpdateModeDelta {
		t.Fatalf("with parent-update:delta, mode = %q, want delta", got)
	}

	// Operator chooses replace explicitly.
	kdb.SetOptions(map[AuthOption]string{AuthOptParentUpdate: UpdateModeReplace})
	if got := proxyUpdateMode(kdb); got != UpdateModeReplace {
		t.Fatalf("with parent-update:replace, mode = %q, want replace", got)
	}
}

// U-d: proxyCurrentDelegationRRs reads the current authoritative NS + glue + DS
// (DS derived from apex DNSKEY SEP keys) from the served zone.
func TestProxyCurrentDelegationRRs(t *testing.T) {
	kdb := newTestKeyDB(t)
	// A signed delegation: NS + in-bailiwick glue + a KSK DNSKEY (SEP) → DS.
	zoneStr := `upd.example.	3600 IN SOA ns1.upd.example. hostmaster.upd.example. 1 7200 1800 604800 3600
upd.example.	3600 IN NS ns1.upd.example.
upd.example.	3600 IN NS ns2.upd.example.
ns1.upd.example.	3600 IN A 192.0.2.1
ns1.upd.example.	3600 IN AAAA 2001:db8::1
ns2.upd.example.	3600 IN A 192.0.2.2
upd.example.	3600 IN DNSKEY 257 3 15 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=
`
	zd := proxyUpdZoneData(t, kdb, zoneStr)
	newNS, newA, newAAAA, newDS := zd.proxyCurrentDelegationRRs()
	if len(newNS) != 2 {
		t.Fatalf("NS = %d, want 2", len(newNS))
	}
	if len(newA) != 2 {
		t.Fatalf("A glue = %d, want 2", len(newA))
	}
	if len(newAAAA) != 1 {
		t.Fatalf("AAAA glue = %d, want 1", len(newAAAA))
	}
	if len(newDS) != 1 {
		t.Fatalf("DS (from KSK DNSKEY) = %d, want 1", len(newDS))
	}
	if _, ok := newDS[0].(*dns.DS); !ok {
		t.Fatalf("DS RR has wrong type %T", newDS[0])
	}
}

// U-d: an unsigned zone (no DNSKEYs) yields NS + glue but no DS — the case the
// UPDATE path serves that NOTIFY cannot.
func TestProxyCurrentDelegationRRsUnsigned(t *testing.T) {
	kdb := newTestKeyDB(t)
	zoneStr := `upd.example.	3600 IN SOA ns1.upd.example. hostmaster.upd.example. 1 7200 1800 604800 3600
upd.example.	3600 IN NS ns1.upd.example.
ns1.upd.example.	3600 IN A 192.0.2.1
`
	zd := proxyUpdZoneData(t, kdb, zoneStr)
	newNS, newA, _, newDS := zd.proxyCurrentDelegationRRs()
	if len(newNS) != 1 || len(newA) != 1 {
		t.Fatalf("NS/A = %d/%d, want 1/1", len(newNS), len(newA))
	}
	if len(newDS) != 0 {
		t.Fatalf("unsigned zone must yield no DS, got %d", len(newDS))
	}
}

// U-c: startup reconcile with no imr (no DSYNC discovery possible) reports
// update-unsupported and does not attempt any parent compare or send. This
// exercises the not-ready early-return branch without the network.
func TestProxyStartupReconcileNotReady(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := proxyUpdZoneData(t, kdb, proxyUpdBaseZone())
	msg, err := zd.ProxyStartupReconcile(context.Background(), kdb, nil)
	if err != nil {
		t.Fatalf("ProxyStartupReconcile (nil imr): unexpected error: %v", err)
	}
	if !strings.Contains(msg, "not ready") {
		t.Fatalf("expected a not-ready message, got %q", msg)
	}
}

// U-a2: ProxyKeyStatus reports an error for a non-proxy zone, and the
// update-unsupported message when no UPDATE target is discoverable (nil imr).
func TestProxyKeyStatus(t *testing.T) {
	kdb := newTestKeyDB(t)

	// Zone without the proxy option ⇒ error.
	zdPlain := proxyUpdZoneData(t, kdb, proxyUpdBaseZone())
	if _, err := zdPlain.ProxyKeyStatus(context.Background(), kdb, nil); err == nil {
		t.Fatal("ProxyKeyStatus must error for a non-proxy zone")
	}

	// Proxy zone, no imr ⇒ update-unsupported message (nothing to publish).
	zdProxy := proxyUpdZoneData(t, kdb, proxyUpdBaseZone())
	zdProxy.Options = map[ZoneOption]bool{OptDelSyncProxy: true}
	msg, err := zdProxy.ProxyKeyStatus(context.Background(), kdb, nil)
	if err != nil {
		t.Fatalf("ProxyKeyStatus (proxy, no imr): %v", err)
	}
	if !strings.Contains(msg, "not applicable") {
		t.Fatalf("expected update-unsupported message, got %q", msg)
	}
}
