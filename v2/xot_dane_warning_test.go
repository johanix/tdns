/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
)

// DANE while DNSSEC validation is not enforced is accepted (Johan's ruling:
// warn loudly, do not refuse). These pin that it is said where the operator
// looks: the API add/modify response, the log at config load, `zone desc`,
// and daemon status.

func daneTestPrimary() PeerConf {
	return PeerConf{Addr: "192.0.2.1:853", Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthDANE, TLSName: "ns1.example."}
}

func notEnforcedConf(enforced bool) *Config {
	conf := &Config{}
	conf.Imr.RequireDnssecValidation = &enforced
	return conf
}

func TestDanePrimaryWarnings(t *testing.T) {
	discard := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	pin := PeerConf{Addr: "192.0.2.2:853", Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthPin,
		Pins: []string{base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))}}
	plain := PeerConf{Addr: "192.0.2.3:53", Key: NOKEY}
	// As an API caller may send it, before validatePeerXoT normalizes it.
	unnormalized := PeerConf{Addr: "192.0.2.4:853", Key: NOKEY, Transport: "DoT", TLSAuth: " DANE ", TLSName: "ns4.example."}
	primaries := []PeerConf{daneTestPrimary(), pin, plain, unnormalized}

	got := notEnforcedConf(false).danePrimaryWarnings(discard, "example.", primaries)
	if len(got) != 2 {
		t.Fatalf("got %d warnings, want 2 (the two dane primaries): %q", len(got), got)
	}
	want := "zone example.: primary 192.0.2.1:853: DANE without DNSSEC validation (imrengine.require-dnssec-validation: false): the TLSA record is not validated, so the certificate check proves nothing"
	if got[0] != want {
		t.Errorf("warning =\n  %q\nwant\n  %q", got[0], want)
	}
	if !strings.Contains(got[1], "primary 192.0.2.4:853:") {
		t.Errorf("unnormalized dane primary not named: %q", got[1])
	}

	if got := notEnforcedConf(true).danePrimaryWarnings(discard, "example.", primaries); got != nil {
		t.Errorf("validation enforced, yet warned: %q", got)
	}
}

func TestDaneDownstreamWarnings(t *testing.T) {
	discard := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	daneEntry := AclEntry{Prefix: "192.0.2.0/24", Key: NOKEY, PeerName: "sec1",
		TLSIdentity: &TLSIdentity{Name: "sec1.example.", Dane: true}}
	pinEntry := AclEntry{Prefix: "198.51.100.0/24", Key: NOKEY,
		TLSIdentity: &TLSIdentity{Name: "sec2.example.", Pins: []string{"x"}}}
	blocked := AclEntry{Prefix: "203.0.113.0/24", Key: BLOCKED,
		TLSIdentity: &TLSIdentity{Name: "sec3.example.", Dane: true}}
	acl := []AclEntry{daneEntry, pinEntry, blocked}

	for _, tc := range []struct {
		name     string
		mechs    []string
		enforced bool
		want     int
	}{
		{"tls-dane allowed", []string{MechTLSPin, MechTLSDane}, false, 1},
		{"tls-dane allowed, unnormalized", []string{"TLS-DANE"}, false, 1},
		{"tls-dane not allowed", []string{MechTLSPin}, false, 0},
		{"any skips every TLS check", []string{MechTLSDane, MechAny}, false, 0},
		{"no ladder", nil, false, 0},
		{"validation enforced", []string{MechTLSDane}, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := notEnforcedConf(tc.enforced).daneDownstreamWarnings(discard, "example.", tc.mechs, acl)
			if len(got) != tc.want {
				t.Fatalf("got %d warnings, want %d: %q", len(got), tc.want, got)
			}
			if tc.want == 1 && !strings.Contains(got[0], "zone example.: downstream sec1.example. (peer sec1): DANE without DNSSEC validation") {
				t.Errorf("warning does not name zone and downstream: %q", got[0])
			}
		})
	}
}

// TestDaneWarningsAtConfigLoad: ParseZones logs the warning at WARN for a
// static secondary with a dane primary and for a tls-dane downstream, and is
// quiet when validation is enforced.
func TestDaneWarningsAtConfigLoad(t *testing.T) {
	parse := func(t *testing.T, enforced bool) string {
		t.Helper()
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		t.Cleanup(func() { slog.SetDefault(prev) })

		conf := notEnforcedConf(enforced)
		conf.Zones = []ZoneConf{
			{
				Name: "dane-sec.example.", Type: "secondary", Store: "map",
				Primaries: []PeerConf{daneTestPrimary(), {Addr: "192.0.2.2", Key: NOKEY}},
			},
			{
				Name: "dane-pri.example.", Type: "primary", Store: "map", Zonefile: "/nonexistent",
				DownstreamAuth: []string{MechTLSDane},
				Downstreams: []AclEntry{{Prefix: "192.0.2.0/24", Key: NOKEY, PeerName: "sec1",
					TLSIdentity: &TLSIdentity{Name: "sec1.example.", Dane: true}}},
			},
		}
		conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
		if _, _, err := conf.ParseZones(context.Background(), false); err != nil {
			t.Fatalf("ParseZones: %v", err)
		}
		Zones.Remove("dane-sec.example.")
		Zones.Remove("dane-pri.example.")
		return buf.String()
	}

	out := parse(t, false)
	var primaryLine, downstreamLine string
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "DANE without DNSSEC validation") {
			continue
		}
		if !strings.Contains(line, "level=WARN") {
			t.Errorf("not logged at WARN: %s", line)
		}
		switch {
		case strings.Contains(line, "zone=dane-sec.example.") && strings.Contains(line, "primary=192.0.2.1:853"):
			primaryLine = line
		case strings.Contains(line, "zone=dane-pri.example.") && strings.Contains(line, "sec1.example."):
			downstreamLine = line
		case strings.Contains(line, "192.0.2.2"):
			t.Errorf("warned about a plain Do53 primary: %s", line)
		}
	}
	if primaryLine == "" {
		t.Errorf("no warning for the dane primary\n--- log ---\n%s", out)
	}
	if downstreamLine == "" {
		t.Errorf("no warning for the tls-dane downstream\n--- log ---\n%s", out)
	}

	if out := parse(t, true); strings.Contains(out, "DANE without DNSSEC validation") {
		t.Errorf("validation enforced, yet warned\n--- log ---\n%s", out)
	}
}

// TestDaneWarningsAtDynamicZoneLoad: LoadDynamicZoneFiles logs the warning at
// boot for persisted zones on both of its paths: a template-based primary with
// a tls-dane downstream (re-expanded from the template), and a plain secondary
// with a dane primary. Quiet when validation is enforced.
func TestDaneWarningsAtDynamicZoneLoad(t *testing.T) {
	load := func(t *testing.T, enforced bool) string {
		t.Helper()
		resetZonesForTest()
		t.Cleanup(resetZonesForTest)
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		t.Cleanup(func() { slog.SetDefault(prev) })

		conf, _ := newTestConfigForCores(t)
		conf.Imr.RequireDnssecValidation = &enforced
		dir := t.TempDir()
		tmpl := dynPrimaryTestTemplate(dir)
		tmpl.DownstreamAuth = []string{MechTLSDane}
		tmpl.Downstreams = []AclEntry{{Prefix: "127.0.0.1/32", Key: NOKEY, PeerName: "sec1",
			TLSIdentity: &TLSIdentity{Name: "sec1.example.", Dane: true}}}
		withTestTemplates(t, map[string]ZoneConf{"dyn-test": tmpl})

		zonefile := filepath.Join(dir, "boot.example.zone")
		if err := os.WriteFile(zonefile, []byte("boot.example.\t3600\tIN\tSOA\tns.boot.example. h.boot.example. 1 3600 600 604800 300\nboot.example.\t3600\tIN\tNS\tns.boot.example.\n"), 0644); err != nil {
			t.Fatal(err)
		}
		dynCfg := filepath.Join(dir, "dynamic-zones.yaml")
		cfgYaml := `zones:
  - name: boot.example.
    type: primary
    store: map
    template: dyn-test
    zonefile: ` + zonefile + `
    apimanaged: true
  - name: sec.example.
    type: secondary
    store: map
    apimanaged: true
    primaries:
      - addr: 192.0.2.1:853
        key: NOKEY
        transport: dot
        tls-auth: dane
        tls-name: ns1.example.
`
		if err := os.WriteFile(dynCfg, []byte(cfgYaml), 0644); err != nil {
			t.Fatal(err)
		}
		conf.DynamicZones.ConfigFile = dynCfg
		conf.DynamicZones.ZoneDirectory = dir

		if err := conf.LoadDynamicZoneFiles(context.Background()); err != nil {
			t.Fatalf("LoadDynamicZoneFiles: %v", err)
		}
		return buf.String()
	}

	out := load(t, false)
	var templateLine, secondaryLine bool
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "DANE without DNSSEC validation") {
			continue
		}
		if !strings.Contains(line, "level=WARN") {
			t.Errorf("not logged at WARN: %s", line)
		}
		if strings.Contains(line, "zone=boot.example.") && strings.Contains(line, "sec1.example.") {
			templateLine = true
		}
		if strings.Contains(line, "zone=sec.example.") && strings.Contains(line, "primary=192.0.2.1:853") {
			secondaryLine = true
		}
	}
	if !templateLine {
		t.Errorf("no warning for the template primary's tls-dane downstream\n--- log ---\n%s", out)
	}
	if !secondaryLine {
		t.Errorf("no warning for the persisted secondary's dane primary\n--- log ---\n%s", out)
	}

	if out := load(t, true); strings.Contains(out, "DANE without DNSSEC validation") {
		t.Errorf("validation enforced, yet warned\n--- log ---\n%s", out)
	}
}

// TestDaneWarningsInZoneAPIResponse drives the /zone API handler: an add or a
// modify that leaves the zone with a dane primary carries the warning in the
// response, and the operation is still accepted.
func TestDaneWarningsInZoneAPIResponse(t *testing.T) {
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)

	// The handler uses the global Conf. Save and restore what this touches.
	prevCh, prevAllowed := Conf.Internal.RefreshZoneCh, Conf.DynamicZones.Dynamic.Allowed
	prevRequire, prevActive, prevReady := Conf.Imr.RequireDnssecValidation, Conf.Imr.Active, Conf.Internal.ImrReady
	prevFile := Conf.DynamicZones.ConfigFile
	t.Cleanup(func() {
		Conf.Internal.RefreshZoneCh, Conf.DynamicZones.Dynamic.Allowed = prevCh, prevAllowed
		Conf.Imr.RequireDnssecValidation, Conf.Imr.Active, Conf.Internal.ImrReady = prevRequire, prevActive, prevReady
		Conf.DynamicZones.ConfigFile = prevFile
	})
	Conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 16)
	Conf.DynamicZones.Dynamic.Allowed = ZoneTypeList{"secondary"}
	Conf.Imr.Active, Conf.Internal.ImrReady = nil, nil // the configured setting decides
	Conf.DynamicZones.ConfigFile = ""                  // no persistence

	handler := APIzone(&AppDetails{Name: "tdns-auth"}, Conf.Internal.RefreshZoneCh, nil)
	post := func(t *testing.T, zp ZonePost) ZoneResponse {
		t.Helper()
		body, err := json.Marshal(zp)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodPost, "/api/v1/zone", bytes.NewReader(body)))
		var resp ZoneResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding response: %v\n%s", err, rec.Body.String())
		}
		if resp.Error {
			t.Fatalf("%s refused: %s", zp.Command, resp.ErrorMsg)
		}
		return resp
	}
	pin := PeerConf{Addr: "192.0.2.2:853", Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthPin,
		Pins: []string{base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))}}
	wantDane := "zone dane-api.example.: primary 192.0.2.1:853: DANE without DNSSEC validation"

	notEnforced, enforced := false, true
	Conf.Imr.RequireDnssecValidation = &notEnforced

	resp := post(t, ZonePost{Command: "add", Zone: "dane-api.example", Primaries: []PeerConf{daneTestPrimary()}})
	if len(resp.Warnings) != 1 || !strings.HasPrefix(resp.Warnings[0], wantDane) {
		t.Errorf("add: warnings = %q, want one starting %q", resp.Warnings, wantDane)
	}
	if resp.Status != "accepted" {
		t.Errorf("add: status = %q, want accepted (warn, do not refuse)", resp.Status)
	}

	// A modify that keeps the primaries: the zone still uses DANE.
	resp = post(t, ZonePost{Command: "modify", Zone: "dane-api.example"})
	if len(resp.Warnings) != 1 || !strings.HasPrefix(resp.Warnings[0], wantDane) {
		t.Errorf("modify (primaries kept): warnings = %q, want one starting %q", resp.Warnings, wantDane)
	}

	// A modify to a pinned primary: nothing to warn about.
	resp = post(t, ZonePost{Command: "modify", Zone: "dane-api.example", Primaries: []PeerConf{pin}})
	if len(resp.Warnings) != 0 {
		t.Errorf("modify to a pin primary: warnings = %q, want none", resp.Warnings)
	}

	// And back to dane, through modify.
	resp = post(t, ZonePost{Command: "modify", Zone: "dane-api.example", Primaries: []PeerConf{daneTestPrimary()}})
	if len(resp.Warnings) != 1 || !strings.HasPrefix(resp.Warnings[0], wantDane) {
		t.Errorf("modify to a dane primary: warnings = %q, want one starting %q", resp.Warnings, wantDane)
	}

	// Validation enforced: the same add is quiet.
	Conf.Imr.RequireDnssecValidation = &enforced
	resp = post(t, ZonePost{Command: "add", Zone: "dane-api2.example", Primaries: []PeerConf{daneTestPrimary()}})
	if len(resp.Warnings) != 0 {
		t.Errorf("add with validation enforced: warnings = %q, want none", resp.Warnings)
	}
}

// TestProbeUpstreamSerialsFlagsUnvalidatedTLSA: the per-primary serial probe
// behind `zone desc` flags a dane primary whose TLSA record it took without
// DNSSEC validation, and only then.
func TestProbeUpstreamSerialsFlagsUnvalidatedTLSA(t *testing.T) {
	zd := loadTestTransferZone(t, basicZone)
	cert, leaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, zd, nil, cert)
	defer srv.shutdown()
	port := serverPort(t, srv)
	peer := PeerConf{Addr: srv.addr, Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthDANE, TLSName: "ns1.test"}

	for _, tc := range []struct {
		state         cache.ValidationState
		requireSecure bool
		wantWarning   bool
		wantErr       bool
	}{
		{cache.ValidationStateSecure, false, false, false},
		{cache.ValidationStateSecure, true, false, false},
		{cache.ValidationStateInsecure, false, true, false},
		{cache.ValidationStateNone, false, true, false},
		{cache.ValidationStateInsecure, true, false, true}, // fails closed, as before
	} {
		name := fmt.Sprintf("%s/require=%v", cache.ValidationStateToString[tc.state], tc.requireSecure)
		t.Run(name, func(t *testing.T) {
			conf := daneTestConf(t, leaf, port, tc.state, tc.requireSecure)
			got := newTestSecondary(t, peer).ProbeUpstreamSerials(context.Background(), conf)
			if len(got) != 1 {
				t.Fatalf("got %d results, want 1", len(got))
			}
			us := got[0]
			if (us.Err != "") != tc.wantErr {
				t.Fatalf("Err = %q, want error: %v", us.Err, tc.wantErr)
			}
			if !tc.wantErr && us.Serial != 1 {
				t.Errorf("Serial = %d, want 1", us.Serial)
			}
			if (us.Warning == TLSANotValidatedWarning) != tc.wantWarning || (us.Warning != "" && us.Warning != TLSANotValidatedWarning) {
				t.Errorf("Warning = %q, want warning: %v", us.Warning, tc.wantWarning)
			}
		})
	}
}

// TestDaneZonesWarning: daemon status names the zones that use DANE while
// validation is not enforced, capped, and says nothing otherwise.
func TestDaneZonesWarning(t *testing.T) {
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)

	Zones.Set("plain.example.", &ZoneData{ZoneName: "plain.example.", PrimariesConf: []PeerConf{{Addr: "192.0.2.3:53", Key: NOKEY}}})
	Zones.Set("dane.example.", &ZoneData{ZoneName: "dane.example.", PrimariesConf: []PeerConf{daneTestPrimary()}})
	Zones.Set("down.example.", &ZoneData{ZoneName: "down.example.", DownstreamAuth: []string{MechTLSDane},
		Downstreams: []AclEntry{{Prefix: "192.0.2.0/24", Key: NOKEY, TLSIdentity: &TLSIdentity{Name: "sec1.example.", Dane: true}}}})

	if w := notEnforcedConf(true).daneZonesWarning(); w != "" {
		t.Errorf("validation enforced, yet warned: %q", w)
	}
	w := notEnforcedConf(false).daneZonesWarning()
	if !strings.HasPrefix(w, "DANE without DNSSEC validation in 2 zone(s): dane.example., down.example.:") {
		t.Errorf("warning = %q", w)
	}
	if strings.Contains(w, "plain.example.") {
		t.Errorf("named a zone that does not use DANE: %q", w)
	}

	for i := 0; i < daneWarningZonesShown; i++ {
		name := fmt.Sprintf("z%02d.example.", i)
		Zones.Set(name, &ZoneData{ZoneName: name, PrimariesConf: []PeerConf{daneTestPrimary()}})
	}
	w = notEnforcedConf(false).daneZonesWarning()
	if !strings.Contains(w, fmt.Sprintf("in %d zone(s)", daneWarningZonesShown+2)) || !strings.Contains(w, " and 2 more:") {
		t.Errorf("capped warning = %q", w)
	}
}
