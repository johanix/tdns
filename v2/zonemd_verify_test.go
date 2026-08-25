package tdns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// vzBase is a small unsigned zone. Its digest is computed rather than
// hard-coded, because these tests are about the VERDICT logic; the digest
// values themselves are pinned against dnspython in zonemd_test.go.
const vzBase = `vz.example.	3600	IN	SOA	ns.vz.example. hostmaster.vz.example. 42 7200 1800 604800 7200
vz.example.	3600	IN	NS	ns.vz.example.
ns.vz.example.	3600	IN	A	192.0.2.1
alpha.vz.example.	3600	IN	A	10.0.0.1
`

// vzZone builds the RR list for a zone plus a ZONEMD line, and returns both
// the records and the correct digest for the given parameters.
func vzZone(t *testing.T, zonemdLine string) []dns.RR {
	t.Helper()
	return parseZoneRRs(t, "vz.example.", vzBase+zonemdLine)
}

func vzCorrectDigest(t *testing.T, alg uint8) string {
	t.Helper()
	d, err := ZoneDigestHex("vz.example.", parseZoneRRs(t, "vz.example.", vzBase),
		ZonemdSchemeSimple, alg)
	if err != nil {
		t.Fatalf("computing the reference digest: %v", err)
	}
	return d
}

func vzVerify(t *testing.T, rrs []dns.RR, opts VerifyZonemdOpts) *ZonemdReport {
	t.Helper()
	r, err := VerifyZonemd("vz.example.", rrs, opts)
	if err != nil {
		t.Fatalf("VerifyZonemd: %v", err)
	}
	return r
}

// A zone with no ZONEMD has not failed anything. Most zones do not publish one,
// and a verifier that calls that a failure is a verifier nobody can enable.
func TestVerifyZonemdAbsent(t *testing.T) {
	r := vzVerify(t, vzZone(t, ""), VerifyZonemdOpts{})
	if r.Verdict != "absent" {
		t.Errorf("a zone with no ZONEMD reported %q", r.Verdict)
	}
	if r.SoaSerial != 42 {
		t.Errorf("SOA serial reported as %d", r.SoaSerial)
	}
}

func TestVerifyZonemdValid(t *testing.T) {
	line := fmt.Sprintf("vz.example.\t3600\tIN\tZONEMD\t42 1 1 %s\n",
		vzCorrectDigest(t, ZonemdAlgSHA384))
	r := vzVerify(t, vzZone(t, line), VerifyZonemdOpts{})
	if r.Verdict != "valid" {
		t.Fatalf("a correct ZONEMD reported %q: %s", r.Verdict, r.Summary())
	}
	if len(r.Checks) != 1 || !r.Checks[0].OK() {
		t.Errorf("the check did not pass: %+v", r.Checks)
	}
}

// Both algorithms, both correct.
func TestVerifyZonemdValidWithTwoAlgorithms(t *testing.T) {
	line := fmt.Sprintf("vz.example.\t3600\tIN\tZONEMD\t42 1 1 %s\n"+
		"vz.example.\t3600\tIN\tZONEMD\t42 1 2 %s\n",
		vzCorrectDigest(t, ZonemdAlgSHA384), vzCorrectDigest(t, ZonemdAlgSHA512))
	r := vzVerify(t, vzZone(t, line), VerifyZonemdOpts{})
	if r.Verdict != "valid" {
		t.Fatalf("two correct ZONEMDs reported %q: %s", r.Verdict, r.Summary())
	}
	if len(r.Checks) != 2 {
		t.Fatalf("expected two checks, got %d", len(r.Checks))
	}
}

func TestVerifyZonemdInvalidDigest(t *testing.T) {
	line := "vz.example.\t3600\tIN\tZONEMD\t42 1 1 " + strings.Repeat("ab", 48) + "\n"
	r := vzVerify(t, vzZone(t, line), VerifyZonemdOpts{})
	if r.Verdict != "invalid" {
		t.Fatalf("a wrong digest reported %q", r.Verdict)
	}
	c := r.Checks[0]
	if !c.Supported || !c.SerialMatch || c.DigestMatch {
		t.Errorf("the check does not say WHY it failed: %+v", c)
	}
	if c.Computed == "" {
		t.Error("the computed digest is not reported, so an operator cannot compare")
	}
}

// RFC 8976 binds the digest to a serial. A ZONEMD naming a different one does
// not describe this zone, whatever its digest says.
func TestVerifyZonemdSerialMismatchIsInvalid(t *testing.T) {
	line := fmt.Sprintf("vz.example.\t3600\tIN\tZONEMD\t41 1 1 %s\n",
		vzCorrectDigest(t, ZonemdAlgSHA384))
	r := vzVerify(t, vzZone(t, line), VerifyZonemdOpts{})
	if r.Verdict != "invalid" {
		t.Fatalf("a ZONEMD naming the wrong serial reported %q", r.Verdict)
	}
	if !strings.Contains(r.Checks[0].Reason, "41") || !strings.Contains(r.Checks[0].Reason, "42") {
		t.Errorf("the reason does not name both serials: %q", r.Checks[0].Reason)
	}
}

// IgnoreSerial answers "was this digest right for the serial it claims?" -- a
// diagnostic, and one that must still say the zone is not serving that serial.
func TestVerifyZonemdIgnoreSerial(t *testing.T) {
	// The digest the zone WOULD have had at serial 41.
	at41 := strings.Replace(vzBase, " 42 7200", " 41 7200", 1)
	d41, err := ZoneDigestHex("vz.example.", parseZoneRRs(t, "vz.example.", at41),
		ZonemdSchemeSimple, ZonemdAlgSHA384)
	if err != nil {
		t.Fatal(err)
	}
	line := fmt.Sprintf("vz.example.\t3600\tIN\tZONEMD\t41 1 1 %s\n", d41)
	rrs := vzZone(t, line)

	// Without the flag: invalid, because the zone is serving 42.
	if r := vzVerify(t, rrs, VerifyZonemdOpts{}); r.Verdict != "invalid" {
		t.Fatalf("a stale-serial ZONEMD reported %q without --ignore-serial", r.Verdict)
	}

	// With it: the digest is confirmed correct for serial 41, and the report
	// says the zone is nonetheless serving 42.
	r := vzVerify(t, rrs, VerifyZonemdOpts{IgnoreSerial: true})
	if r.Verdict != "valid" {
		t.Fatalf("--ignore-serial reported %q: %s", r.Verdict, r.Summary())
	}
	if !r.IgnoredSerial {
		t.Error("the report does not record that the serial was ignored")
	}
	if !strings.Contains(r.Checks[0].Reason, "serving serial 42") {
		t.Errorf("--ignore-serial reports a bare OK rather than saying the zone has"+
			" moved on: %q", r.Checks[0].Reason)
	}
}

// A scheme or algorithm this build does not implement is not a zone in
// trouble. Reserved codepoints exist so a publisher can say "not for you", and
// treating unsupported as invalid would make every future algorithm an outage.
func TestVerifyZonemdUnsupportedIsNotInvalid(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
	}{
		{"reserved scheme 0", "vz.example.\t3600\tIN\tZONEMD\t42 0 1 " + strings.Repeat("ab", 48)},
		{"unknown scheme", "vz.example.\t3600\tIN\tZONEMD\t42 9 1 " + strings.Repeat("ab", 48)},
		{"reserved algorithm 0", "vz.example.\t3600\tIN\tZONEMD\t42 1 0 " + strings.Repeat("ab", 48)},
		{"unknown algorithm", "vz.example.\t3600\tIN\tZONEMD\t42 1 7 " + strings.Repeat("ab", 48)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := vzVerify(t, vzZone(t, tc.line+"\n"), VerifyZonemdOpts{})
			if r.Verdict != "unsupported" {
				t.Fatalf("reported %q, not unsupported: %s", r.Verdict, r.Summary())
			}
			if r.Checks[0].Supported {
				t.Error("the check claims the parameters are supported")
			}
			if r.Checks[0].Computed != "" {
				t.Error("a digest was computed for parameters we do not implement")
			}
		})
	}
}

// One supported ZONEMD alongside one we cannot check: the supported one
// decides. Nothing is learned from the other, and nothing is claimed about it.
func TestVerifyZonemdSupportedAlongsideUnsupported(t *testing.T) {
	line := fmt.Sprintf("vz.example.\t3600\tIN\tZONEMD\t42 1 1 %s\n"+
		"vz.example.\t3600\tIN\tZONEMD\t42 1 7 %s\n",
		vzCorrectDigest(t, ZonemdAlgSHA384), strings.Repeat("ab", 48))
	r := vzVerify(t, vzZone(t, line), VerifyZonemdOpts{})
	if r.Verdict != "valid" {
		t.Fatalf("reported %q; the supported ZONEMD verified: %s", r.Verdict, r.Summary())
	}
}

// The (scheme, algorithm) pair is what names which digest a verifier looked
// at, so two RRs sharing one leave it unable to say what it checked.
func TestVerifyZonemdDuplicatePairIsInvalid(t *testing.T) {
	d := vzCorrectDigest(t, ZonemdAlgSHA384)
	line := fmt.Sprintf("vz.example.\t3600\tIN\tZONEMD\t42 1 1 %s\n"+
		"vz.example.\t3600\tIN\tZONEMD\t42 1 1 %s\n", d, strings.Repeat("ab", 48))
	r := vzVerify(t, vzZone(t, line), VerifyZonemdOpts{})
	if r.Verdict != "invalid" {
		t.Fatalf("a duplicate (scheme, algorithm) pair reported %q", r.Verdict)
	}
}

// A zone with no SOA is not a zone, and a digest with no serial to bind to is
// not something to return a verdict about.
func TestVerifyZonemdWithoutSoaIsAnError(t *testing.T) {
	rrs := parseZoneRRs(t, "vz.example.", "vz.example.\t3600\tIN\tNS\tns.vz.example.\n")
	if _, err := VerifyZonemd("vz.example.", rrs, VerifyZonemdOpts{}); err == nil {
		t.Fatal("a zone with no SOA produced a verdict")
	}
}

// The round trip that matters: what this server publishes, this server (and
// therefore any other correct implementation) verifies.
func TestPublishedZonemdVerifies(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)

	r, err := zd.VerifyZonemdOfPublished(VerifyZonemdOpts{})
	if err != nil {
		t.Fatalf("verifying the published zone: %v", err)
	}
	if r.Verdict != "valid" {
		t.Fatalf("the zone does not verify against itself: %s", r.Summary())
	}
}

// ---- the verify-zonemd gate ----

const vzGateBase = `example.	3600	IN	SOA	ns.example. hostmaster.example. 100 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
`

// gateZoneText returns the base zone plus a ZONEMD, correct or corrupt.
func gateZoneText(t *testing.T, correct bool) string {
	t.Helper()
	digest := strings.Repeat("ab", 48)
	if correct {
		d, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", vzGateBase),
			ZonemdSchemeSimple, ZonemdAlgSHA384)
		if err != nil {
			t.Fatal(err)
		}
		digest = d
	}
	return vzGateBase + "example.\t3600\tIN\tZONEMD\t100 1 1 " + digest + "\n"
}

// A zone whose digest does not describe it is refused, and the server goes on
// serving what it had. This is the whole point of the option: a secondary
// cannot re-derive a digest it was not given, so checking the one it WAS given
// is its only assurance.
func TestVerifyZonemdGateRefusesACorruptZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, vzGateBase)
	zd.SetOption(OptVerifyZonemd, true)
	before := zd.publishedSnapshot().Serial

	// Replace the file with one whose ZONEMD is wrong, and advance the serial
	// so the reload would otherwise adopt it.
	bad := strings.Replace(gateZoneText(t, false), " 100 7200", " 101 7200", 1)
	bad = strings.Replace(bad, "ZONEMD\t100 1 1", "ZONEMD\t101 1 1", 1)
	operatorEdit(t, zd, bad)

	updated, err := zd.Refresh(context.Background(), false, false, false, &Config{})
	if err == nil {
		t.Fatal("a zone whose ZONEMD does not describe it was adopted without complaint")
	}
	if updated {
		t.Error("the refresh reported the zone as updated")
	}
	if !strings.Contains(err.Error(), "ZONEMD") {
		t.Errorf("the refusal does not say what failed: %v", err)
	}
	if got := zd.publishedSnapshot().Serial; got != before {
		t.Errorf("the zone stopped serving what it had: serial %d, was %d", got, before)
	}
	if _, ok := zd.publishedSnapshot().Data["www.example."]; !ok {
		t.Error("the previously served content is gone")
	}
}

// ...and a zone whose digest does describe it is adopted normally.
func TestVerifyZonemdGateAcceptsAGoodZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, vzGateBase)
	zd.SetOption(OptVerifyZonemd, true)

	good := strings.Replace(gateZoneText(t, true), "www.example.\t3600\tIN\tA\t192.0.2.1",
		"www.example.\t3600\tIN\tA\t192.0.2.1\nnew.example.\t3600\tIN\tA\t10.0.0.9", 1)
	// Recompute for the zone as edited, and advance the serial.
	good = strings.Replace(good, " 100 7200", " 101 7200", 1)
	body := strings.Split(good, "example.\t3600\tIN\tZONEMD")[0]
	d, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", body),
		ZonemdSchemeSimple, ZonemdAlgSHA384)
	if err != nil {
		t.Fatal(err)
	}
	good = body + "example.\t3600\tIN\tZONEMD\t101 1 1 " + d + "\n"
	operatorEdit(t, zd, good)

	if _, err := zd.Refresh(context.Background(), false, false, false, &Config{}); err != nil {
		t.Fatalf("a zone whose ZONEMD describes it was refused: %v", err)
	}
	if _, ok := zd.publishedSnapshot().Data["new.example."]; !ok {
		t.Error("the new content was not adopted")
	}
}

// A zone with no ZONEMD at all is adopted. The option says "check the digest
// if there is one"; making it also mean "refuse a zone that publishes none"
// would be a policy about the upstream's configuration, which is a different
// setting nobody asked for here.
func TestVerifyZonemdGateAcceptsAZoneWithNoZonemd(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, vzGateBase)
	zd.SetOption(OptVerifyZonemd, true)

	operatorEdit(t, zd, strings.Replace(vzGateBase, " 100 7200", " 101 7200", 1)+
		"other.example.\t3600\tIN\tA\t10.0.0.8\n")
	if _, err := zd.Refresh(context.Background(), false, false, false, &Config{}); err != nil {
		t.Fatalf("a zone with no ZONEMD was refused: %v", err)
	}
	if _, ok := zd.publishedSnapshot().Data["other.example."]; !ok {
		t.Error("the zone was not adopted")
	}
}

// on-verify-failure: warn adopts and complains, for the rollout in which the
// first thing an operator needs to know is whether their own primaries pass.
func TestVerifyZonemdGateWarnModeAdopts(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, vzGateBase)
	zd.SetOption(OptVerifyZonemd, true)
	zd.mu.Lock()
	zd.zonemdOnVerifyFailure = ZonemdOnFailureWarn
	zd.mu.Unlock()

	bad := strings.Replace(gateZoneText(t, false), " 100 7200", " 101 7200", 1)
	bad = strings.Replace(bad, "ZONEMD\t100 1 1", "ZONEMD\t101 1 1", 1)
	bad = strings.Replace(bad, "www.example.\t3600\tIN\tA\t192.0.2.1",
		"www.example.\t3600\tIN\tA\t192.0.2.1\nwarned.example.\t3600\tIN\tA\t10.0.0.7", 1)
	operatorEdit(t, zd, bad)

	if _, err := zd.Refresh(context.Background(), false, false, false, &Config{}); err != nil {
		t.Fatalf("warn mode refused the zone: %v", err)
	}
	if _, ok := zd.publishedSnapshot().Data["warned.example."]; !ok {
		t.Error("warn mode did not adopt the zone")
	}
}

// The option off means the check does not run at all, so a corrupt digest is
// not this server's problem.
func TestVerifyZonemdGateIsOffByDefault(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, vzGateBase)

	bad := strings.Replace(gateZoneText(t, false), " 100 7200", " 101 7200", 1)
	bad = strings.Replace(bad, "ZONEMD\t100 1 1", "ZONEMD\t101 1 1", 1)
	operatorEdit(t, zd, bad)

	if _, err := zd.Refresh(context.Background(), false, false, false, &Config{}); err != nil {
		t.Fatalf("a zone was refused without verify-zonemd set: %v", err)
	}
}

// ---- status / verify report ----

func TestZonemdStatusReport(t *testing.T) {
	zd := zonemdTestZone(t)

	// status: reports what is published, and does NOT claim it is right.
	st, err := zd.ZonemdStatusReport(false, VerifyZonemdOpts{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Publishing || st.Verifying {
		t.Errorf("options misreported: publishing=%v verifying=%v", st.Publishing, st.Verifying)
	}
	if len(st.Report.Checks) != 1 {
		t.Fatalf("expected one published ZONEMD, got %d", len(st.Report.Checks))
	}
	if st.Report.Checks[0].Computed != "" {
		t.Error("status recomputed the digest; that is what verify is for")
	}
	if st.Report.Verdict == "valid" {
		t.Error("status reported a verdict of \"valid\" without having checked anything")
	}

	// verify: recomputes and agrees.
	st, err = zd.ZonemdStatusReport(true, VerifyZonemdOpts{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if st.Report.Verdict != "valid" {
		t.Fatalf("verify reported %q: %s", st.Report.Verdict, st.Report.Summary())
	}
	if st.Report.Checks[0].Computed == "" {
		t.Error("verify did not report what it computed")
	}
	if st.OnVerifyFailure != ZonemdOnFailureRefuse {
		t.Errorf("the default failure mode is reported as %q", st.OnVerifyFailure)
	}
}

func TestResolveZonemdConfOnVerifyFailure(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", ZonemdOnFailureRefuse, false},
		{"refuse", ZonemdOnFailureRefuse, false},
		{"warn", ZonemdOnFailureWarn, false},
		{"ignore", "", true},
		{"Warn", "", true}, // case-sensitive: a config value is a config value
	} {
		name := tc.in
		if name == "" {
			name = "(unset)"
		}
		t.Run(name, func(t *testing.T) {
			set, err := resolveZonemdConf(ZonemdConf{OnVerifyFailure: tc.in})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%q was accepted", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q was rejected: %v", tc.in, err)
			}
			if set.OnVerifyFailure != tc.want {
				t.Errorf("%q resolved to %q, want %q", tc.in, set.OnVerifyFailure, tc.want)
			}
		})
	}
}

// verify-zonemd is not origination: a secondary checking what it received is
// exactly the role the option is for, and stripping it would remove the
// feature from the only place it matters.
func TestVerifyZonemdSurvivesOnAMirroringSecondary(t *testing.T) {
	opts := map[ZoneOption]bool{OptVerifyZonemd: true, OptPublishZonemd: true}
	eff, _, suppressed, _ := normalizeOptionsForRole(AppTypeAuth, Secondary, opts, "")
	if !eff[OptVerifyZonemd] || suppressed[OptVerifyZonemd] {
		t.Error("verify-zonemd was stripped from a mirroring secondary, which is the" +
			" role it exists for")
	}
	if eff[OptPublishZonemd] {
		t.Error("publish-zonemd survived, so the two are not being told apart")
	}
}

// ---- the gate on the inbound-transfer path ----

// startRRListAXFRServer serves a fixed record list over AXFR, and answers the
// SOA probe that precedes it.
//
// A ZoneData-backed server cannot be used here: the zone under test must serve
// a ZONEMD that does NOT describe it, which a zone with publish-zonemd would
// by construction never produce.
func startRRListAXFRServer(t *testing.T, zone string, rrs []dns.RR) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var soa dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeSOA {
			soa = rr
			break
		}
	}
	if soa == nil {
		t.Fatal("the record list has no SOA")
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeSOA {
			m.Answer = []dns.RR{soa}
			_ = w.WriteMsg(m)
			return
		}
		// AXFR: SOA, the records, SOA.
		tr := new(dns.Transfer)
		ch := make(chan *dns.Envelope, 1)
		out := append([]dns.RR{soa}, rrs...)
		out = append(out, soa)
		go func() { ch <- &dns.Envelope{RR: out}; close(ch) }()
		_ = tr.Out(w, r, ch)
	})

	started := make(chan struct{})
	srv := &dns.Server{Listener: ln, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("the test AXFR server did not start")
	}
	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	}
}

// upstreamZoneText is the zone the fake primary serves, at a serial ahead of
// what the secondary already has so the transfer is not discarded as unchanged.
func upstreamZoneText(t *testing.T, correctDigest bool) []dns.RR {
	t.Helper()
	const body = `up.example.	3600	IN	SOA	ns.up.example. hostmaster.up.example. 200 7200 1800 604800 7200
up.example.	3600	IN	NS	ns.up.example.
ns.up.example.	3600	IN	A	192.0.2.1
fresh.up.example.	3600	IN	A	10.4.4.4
`
	digest := strings.Repeat("ab", 48)
	if correctDigest {
		d, err := ZoneDigestHex("up.example.", parseZoneRRs(t, "up.example.", body),
			ZonemdSchemeSimple, ZonemdAlgSHA384)
		if err != nil {
			t.Fatal(err)
		}
		digest = d
	}
	return parseZoneRRs(t, "up.example.",
		body+"up.example.\t3600\tIN\tZONEMD\t200 1 1 "+digest+"\n")
}

// secondaryOf builds a Ready secondary already serving some content, pointed
// at addr.
func secondaryOf(t *testing.T, kdb *KeyDB, addr string) *ZoneData {
	t.Helper()
	const held = `up.example.	3600	IN	SOA	ns.up.example. hostmaster.up.example. 100 7200 1800 604800 7200
up.example.	3600	IN	NS	ns.up.example.
held.up.example.	3600	IN	A	192.0.2.9
`
	zd := &ZoneData{
		ZoneName:  "up.example.",
		ZoneStore: MapZone,
		ZoneType:  Secondary,
		Logger:    log.New(os.Stderr, "", 0),
		Options:   map[ZoneOption]bool{OptVerifyZonemd: true},
		KeyDB:     kdb,
		Upstreams: []PeerConf{{Addr: addr, Key: NOKEY}},
	}
	if _, _, err := zd.ReadZoneData(held, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.Ready = true
	zd.IncomingSerial = 100
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.stopPublisher)
	registerZones(t, zd)
	return zd
}

// The case verify-zonemd exists for. A secondary cannot re-derive a digest it
// was not given, so checking the one it WAS given is its only assurance that
// what it is about to serve is what its primary published.
func TestVerifyZonemdGateRefusesACorruptTransfer(t *testing.T) {
	kdb := newTestKeyDB(t)
	addr, stop := startRRListAXFRServer(t, "up.example.", upstreamZoneText(t, false))
	defer stop()

	zd := secondaryOf(t, kdb, addr)
	before := zd.publishedSnapshot().Serial

	updated, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{})
	if err == nil {
		t.Fatal("a transferred zone whose ZONEMD does not describe it was adopted")
	}
	if updated {
		t.Error("the transfer reported the zone as updated")
	}
	if !strings.Contains(err.Error(), "ZONEMD") {
		t.Errorf("the refusal does not say what failed: %v", err)
	}

	snap := zd.publishedSnapshot()
	if snap.Serial != before {
		t.Errorf("the secondary stopped serving what it had: serial %d, was %d",
			snap.Serial, before)
	}
	if _, ok := snap.Data["held.up.example."]; !ok {
		t.Error("the previously held content is gone")
	}
	if _, ok := snap.Data["fresh.up.example."]; ok {
		t.Error("content from the refused transfer reached the served snapshot")
	}
}

// ...and a transfer whose digest does describe it is adopted.
func TestVerifyZonemdGateAcceptsAGoodTransfer(t *testing.T) {
	kdb := newTestKeyDB(t)
	addr, stop := startRRListAXFRServer(t, "up.example.", upstreamZoneText(t, true))
	defer stop()

	zd := secondaryOf(t, kdb, addr)
	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("a transfer whose ZONEMD describes it was refused: %v", err)
	}
	snap := zd.publishedSnapshot()
	if _, ok := snap.Data["fresh.up.example."]; !ok {
		t.Error("the transferred content was not adopted")
	}
	if _, ok := snap.Data["held.up.example."]; ok {
		t.Error("the old content survived a whole-zone replacement")
	}
}

// warn adopts a transfer that fails, for the rollout.
func TestVerifyZonemdGateWarnModeAdoptsATransfer(t *testing.T) {
	kdb := newTestKeyDB(t)
	addr, stop := startRRListAXFRServer(t, "up.example.", upstreamZoneText(t, false))
	defer stop()

	zd := secondaryOf(t, kdb, addr)
	zd.mu.Lock()
	zd.zonemdOnVerifyFailure = ZonemdOnFailureWarn
	zd.mu.Unlock()

	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("warn mode refused the transfer: %v", err)
	}
	if _, ok := zd.publishedSnapshot().Data["fresh.up.example."]; !ok {
		t.Error("warn mode did not adopt the transfer")
	}
}

// Without the option the check does not run, so a corrupt digest upstream is
// not this server's problem.
func TestVerifyZonemdGateOffAdoptsACorruptTransfer(t *testing.T) {
	kdb := newTestKeyDB(t)
	addr, stop := startRRListAXFRServer(t, "up.example.", upstreamZoneText(t, false))
	defer stop()

	zd := secondaryOf(t, kdb, addr)
	zd.SetOption(OptVerifyZonemd, false)

	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("a transfer was refused without verify-zonemd set: %v", err)
	}
	if _, ok := zd.publishedSnapshot().Data["fresh.up.example."]; !ok {
		t.Error("the transfer was not adopted")
	}
}

// The gate digests the whole incoming zone, which for a large one takes real
// time, and it sits between the caller's own cancellation checks. Verifying a
// zone for a daemon on its way out is work nobody will use, and doing it
// delays the shutdown by a full digest -- the same reasoning that puts a check
// in front of the parse and the publish either side of it.
func TestVerifyZonemdGateHonoursCancellation(t *testing.T) {
	kdb := newTestKeyDB(t)
	addr, stop := startRRListAXFRServer(t, "up.example.", upstreamZoneText(t, true))
	defer stop()

	zd := secondaryOf(t, kdb, addr)
	before := zd.publishedSnapshot().Serial

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := zd.FetchFromUpstream(ctx, false, false, false, nil, &Config{}); err == nil {
		t.Fatal("a cancelled transfer was adopted")
	}
	if got := zd.publishedSnapshot().Serial; got != before {
		t.Errorf("a cancelled refresh changed what is served: serial %d, was %d", got, before)
	}

	// And the gate itself reports the cancellation rather than digesting: with
	// a cancelled context it must not reach the verification at all.
	incoming := testZone(t, "up.example.", `up.example.	3600	IN	SOA	ns.up.example. hostmaster.up.example. 200 7200 1800 604800 7200
up.example.	3600	IN	NS	ns.up.example.
`)
	t.Cleanup(incoming.stopPublisher)
	err := zd.gateIncomingZonemd(ctx, incoming, "test")
	if err == nil {
		t.Fatal("the gate ran with a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("the gate did not report the cancellation: %v", err)
	}
}
