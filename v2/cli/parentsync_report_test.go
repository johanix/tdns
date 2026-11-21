/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The parentsync status report as the operator reads it (#790), and the
 * deprecated proxy-key command it replaces.
 */
package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

func renderReport(r *tdns.ParentSyncReport, todo ...string) string {
	var b bytes.Buffer
	printParentSyncReport(&b, "child.example.", r, todo, false)
	return b.String()
}

// mustAppearInOrder fails unless every want is in out, each after the one
// before it.
func mustAppearInOrder(t *testing.T, out string, wants ...string) {
	t.Helper()
	rest := out
	for _, w := range wants {
		i := strings.Index(rest, w)
		if i < 0 {
			t.Fatalf("%q missing, or out of order, in:\n%s", w, out)
		}
		rest = rest[i+len(w):]
	}
}

// fitsWidth fails on any line longer than outputWidth.
func fitsWidth(t *testing.T, out string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if len(l) > outputWidth {
			t.Errorf("line of %d characters (max %d): %q", len(l), outputWidth, l)
		}
	}
}

const (
	proxyKeyRR  = "child.example.\t3600\tIN\tKEY\t256 3 15 46TVWd0l+1KO+ow+GcGUljYQ3SjAakdIeepuqoCZsnQ="
	proxyHsync  = "child.example.\t3600\tIN\tHSYNCPARAM\tpubkey"
	proxyHsyncU = "child.example.\t3600\tIN\tTYPE65286\t\\# 4 00060000"
	dsAdd       = "child.example.\t3600\tIN\tDS\t16282 15 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE0D0AE1E0EB4D5B6F5A7C0D7E"
)

var inSync = tdns.DelegationSyncStatus{InSync: true, Parent: "example.", ZoneName: "child.example."}

// A ready proxy: one line per question, the parent's view of the agent's key,
// and the records only with -v.
func TestParentSyncReportProxyReady(t *testing.T) {
	r := &tdns.ParentSyncReport{
		Role:      "parentsync-proxy",
		Parent:    "example.",
		Validated: true,
		Schemes: []tdns.ParentSyncSchemeReport{
			{Scheme: "UPDATE", Usable: true, Target: "update.example. port 53"},
		},
		Update: &tdns.ParentSyncUpdateReport{
			ProxyState: "ready", ProxyRecords: []string{proxyKeyRR, proxyHsync},
			HaveActiveKey: true, ActiveKeyID: 38310,
			ParentKeyState: "Trusted", ParentKeyAuthenticated: true,
		},
		Delegation: &inSync,
	}
	want := "child.example. (parentsync-proxy)\n" +
		"  parent      example., DSYNC validated\n" +
		"  UPDATE      usable: update.example. port 53\n" +
		"  key         38310, published at the primary\n" +
		"  keystate    trusted\n" +
		"  delegation  in sync\n"
	if got := renderReport(r); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}

	var b bytes.Buffer
	printParentSyncReport(&b, "child.example.", r, nil, true)
	mustAppearInOrder(t, b.String(), want, "\npublished at the primary's apex:\n",
		"child.example. 3600 IN KEY 256 3 15 (\n",
		"        46TVWd0l+1KO+ow+GcGUljYQ3SjAakdIeepuqoCZsnQ= )\n",
		"child.example. 3600 IN HSYNCPARAM pubkey\n")
	fitsWidth(t, b.String())
}

// A proxy waiting for its KEY: what to publish, pasteable, under the rows.
func TestParentSyncReportProxyWaiting(t *testing.T) {
	out := renderReport(&tdns.ParentSyncReport{
		Role:      "parentsync-proxy",
		Parent:    "example.",
		Validated: true,
		Schemes: []tdns.ParentSyncSchemeReport{
			{Scheme: "UPDATE", Reason: "waiting for the KEY at the primary"},
		},
		Update: &tdns.ParentSyncUpdateReport{
			ProxyState: "waiting-for-key", ProxyRecords: []string{proxyKeyRR, proxyHsync},
			ProxyRFC3597: proxyHsyncU, HaveActiveKey: true, ActiveKeyID: 38310,
		},
		Delegation: &inSync,
	})
	want := "child.example. (parentsync-proxy)\n" +
		"  parent      example., DSYNC validated\n" +
		"  UPDATE      skipped: waiting for the KEY at the primary\n" +
		"  delegation  in sync\n" +
		"\n" +
		"publish at the primary's apex:\n" +
		"child.example. 3600 IN KEY 256 3 15 (\n" +
		"        46TVWd0l+1KO+ow+GcGUljYQ3SjAakdIeepuqoCZsnQ= )\n" +
		"child.example. 3600 IN HSYNCPARAM pubkey\n" +
		"; the same HSYNCPARAM in RFC 3597 form:\n" +
		"child.example. 3600 IN TYPE65286 \\# 4 00060000\n"
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

// A KEY record is longer than the width: the key goes inside parentheses,
// and the lines still parse as the same record.
func TestZoneFileLinesFitAndParse(t *testing.T) {
	long := proxyKeyRR
	lines := zoneFileLines(long)
	if len(lines) < 2 || !strings.HasSuffix(lines[0], " (") || !strings.HasSuffix(lines[len(lines)-1], " )") {
		t.Fatalf("not wrapped in parentheses: %q", lines)
	}
	fitsWidth(t, strings.Join(lines, "\n"))
	got, err := dns.NewRR(strings.Join(lines, "\n"))
	if err != nil {
		t.Fatalf("the wrapped record does not parse: %v\n%s", err, strings.Join(lines, "\n"))
	}
	want, _ := dns.NewRR(long)
	if got.String() != want.String() {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Johan's point that started #790: a NOTIFY-only setup sees its NOTIFY state,
// not SIG(0) key talk.
func TestParentSyncReportNotifyOnlyHasNoKeyTalk(t *testing.T) {
	out := renderReport(&tdns.ParentSyncReport{
		Role:      "parentsync",
		Parent:    "example.",
		Validated: true,
		Schemes: []tdns.ParentSyncSchemeReport{
			{Scheme: "NOTIFY", Usable: true, Target: "notify.example. port 53"},
		},
		Notify:     &tdns.ParentSyncNotifyReport{Signed: true, PublishesCDS: true},
		Delegation: &inSync,
	})
	for _, never := range []string{"SIG(0)", "KEY", "UPDATE"} {
		if strings.Contains(out, never) {
			t.Errorf("a NOTIFY-only report mentions %q:\n%s", never, out)
		}
	}
	if !strings.Contains(out, "  signals     zone is signed; CDS: yes, CSYNC: no\n") {
		t.Errorf("NOTIFY detail missing:\n%s", out)
	}
}

func TestParentSyncReportChildUpdate(t *testing.T) {
	out := renderReport(&tdns.ParentSyncReport{
		Role:   "parentsync",
		Parent: "example.",
		Schemes: []tdns.ParentSyncSchemeReport{
			{Scheme: "UPDATE", Usable: true, Target: "update.example. port 53"},
		},
		Update: &tdns.ParentSyncUpdateReport{
			HaveActiveKey: true, ActiveKeyID: 4711, ApexKeyIDs: []uint16{4711},
			ParentKeyState: "Validation Failed", ParentKeyAuthenticated: false,
		},
		Delegation: &inSync,
	}, "add the zone's SIG(0) KEY to child.example. at the primary")

	mustAppearInOrder(t, out,
		"  parent      example., DSYNC not validated\n",
		"  key         4711 at the apex\n",
		"  keystate    validation failed (not authenticated)\n",
		"  delegation  in sync\n",
		"  todo        add the zone's SIG(0) KEY to child.example. at the primary\n",
	)

	out = renderReport(&tdns.ParentSyncReport{
		Role:   "parentsync",
		Update: &tdns.ParentSyncUpdateReport{ParentKeyError: "not asked: there is no active SIG(0) key"},
	})
	mustAppearInOrder(t, out,
		"  key         no active SIG(0) key\n",
		"  keystate    not asked: there is no active SIG(0) key\n",
	)
}

func TestParentSyncReportDelegationOutOfSync(t *testing.T) {
	out := renderReport(&tdns.ParentSyncReport{
		Role:   "parentsync",
		Parent: "example.",
		Delegation: &tdns.DelegationSyncStatus{
			Parent: "example.", ZoneName: "child.example.",
			NsAddsStr:   []string{"child.example.\t3600\tIN\tNS\tns2.child.example."},
			ARemovesStr: []string{"ns1.child.example.\t3600\tIN\tA\t192.0.2.1"},
			DSAddsStr:   []string{dsAdd},
		},
		Warning: "the parent refused the last sync",
	})
	mustAppearInOrder(t, out,
		"  delegation  not in sync:\n",
		"    + NS    ns2.child.example.\n",
		"    - A     ns1.child.example. 192.0.2.1\n",
		"    + DS    16282 15 2 49FD46E6C4B45C55D4AC69CBD3CD34AC\n",
		"                       1AFE51DE0D0AE1E0EB4D5B6F5A7C0D7E\n",
		"  warning     the parent refused the last sync\n",
	)
	fitsWidth(t, out)
}

func TestParentSyncReportWhenThereIsNoPlan(t *testing.T) {
	out := renderReport(&tdns.ParentSyncReport{
		Role:            "parentsync-proxy",
		Parent:          "example.",
		PlanNote:        "no IMR available to discover the parent's DSYNC records",
		DelegationError: "delegation sync not available",
	})
	mustAppearInOrder(t, out,
		"child.example. (parentsync-proxy)\n",
		"  parent      example.\n",
		"  schemes     none evaluated: no IMR available to discover the parent's\n",
		"              DSYNC records\n",
		"  delegation  could not compare: delegation sync not available\n",
	)
	if strings.Contains(out, "validated") {
		t.Errorf("a plan that looked at nothing reports on validation:\n%s", out)
	}

	out = renderReport(&tdns.ParentSyncReport{Role: "parentsync", PlanError: "SERVFAIL from the parent"})
	mustAppearInOrder(t, out, "  parent      (unknown); DSYNC discovery failed: SERVFAIL from the\n",
		"              parent\n")
}

// The three lines that used to be hard-coded are not produced by anything.
func TestParentSyncReportHasNoHardCodedLines(t *testing.T) {
	out := renderReport(&tdns.ParentSyncReport{
		Role: "parentsync", Parent: "example.", Validated: true,
		Delegation: &tdns.DelegationSyncStatus{Parent: "example.", ZoneName: "child.example.",
			NsAddsStr: []string{"x"}},
	})
	for _, gone := range []string{"2024-05-01", "Latest delegation sync transaction", "Time of latest", "Current delegation status"} {
		if strings.Contains(out, gone) {
			t.Errorf("report still says %q:\n%s", gone, out)
		}
	}
}

func TestDelegationDelta(t *testing.T) {
	var b bytes.Buffer
	printDelegationDelta(&b, inSync)
	if got := b.String(); got != "in sync\n" {
		t.Errorf("in sync: %q", got)
	}

	b.Reset()
	printDelegationDelta(&b, tdns.DelegationSyncStatus{
		ZoneName:       "child.example.",
		NsAddsStr:      []string{"child.example.\t3600\tIN\tNS\tns2.child.example."},
		NsRemovesStr:   []string{"child.example.\t3600\tIN\tNS\tns.old.example."},
		AAAAAddsStr:    []string{"ns2.child.example.\t3600\tIN\tAAAA\t2001:db8::53"},
		DSRemovesStr:   []string{dsAdd},
		Unread:         []string{"ns3.child.example. A"},
		AAddsStr:       nil,
		AAAARemovesStr: nil,
	})
	want := "not in sync:\n" +
		"  + NS    ns2.child.example.\n" +
		"  - NS    ns.old.example.\n" +
		"  + AAAA  ns2.child.example. 2001:db8::53\n" +
		"  - DS    16282 15 2 49FD46E6C4B45C55D4AC69CBD3CD34AC\n" +
		"                     1AFE51DE0D0AE1E0EB4D5B6F5A7C0D7E\n" +
		"  no answer for: ns3.child.example. A\n"
	if got := b.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// The parent's answer to an UPDATE, as the bootstrap and sync results word it.
func answer(rcode int, ede uint16, text string) tdns.UpdateResult {
	return tdns.UpdateResult{
		Rcode: rcode, EDEFound: ede != 0, EDECode: ede, EDEMessage: text,
		TargetStatus: map[string]tdns.TargetUpdateStatus{"192.0.2.53:53": {Rcode: rcode}},
	}
}

func TestBootstrapResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		keyid  uint16
		ur     tdns.UpdateResult
		failed bool
		errMsg string
		want   string
		ok     bool
	}{
		{"accepted", 38310, answer(dns.RcodeSuccess, 0, ""), false, "",
			"key 38310: accepted by parent (NOERROR)\n", true},
		{"too soon", 16282, answer(dns.RcodeRefused, 547, "verification failed; retry in 3m12s"), true,
			"the parent's validation of the SIG(0) key failed: ... (EDE 547 ...)",
			"key 16282: refused by parent (EDE 547)\n  verification failed; retry in 3m12s\n", false},
		{"refused, no EDE", 16282, answer(dns.RcodeRefused, 0, ""), true, "refused",
			"key 16282: refused by parent (REFUSED)\n", false},
		{"servfail", 16282, answer(dns.RcodeServerFailure, 0, ""), true, "not final",
			"key 16282: failed at parent (SERVFAIL)\n", false},
		{"never sent", 0, tdns.UpdateResult{}, true, "zone child.example.: failed to lookup DSYNC target: timeout",
			"bootstrap: bootstrap failed:\n  zone child.example.: failed to lookup DSYNC target: timeout\n", false},
		{"accepted, then failed here", 38310, answer(dns.RcodeSuccess, 0, ""), true, "failed to begin transaction",
			"key 38310: accepted by parent (NOERROR), then failed:\n  failed to begin transaction\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			ok := printBootstrapResult(&b, tc.keyid, tc.ur, tc.failed, tc.errMsg)
			if b.String() != tc.want || ok != tc.ok {
				t.Errorf("got %q (%v), want %q (%v)", b.String(), ok, tc.want, tc.ok)
			}
		})
	}
}

func TestRollResult(t *testing.T) {
	var b bytes.Buffer
	if !printRollResult(&b, 16282, 40112, answer(dns.RcodeSuccess, 0, ""), false, "", "") ||
		b.String() != "key 16282: rolled to 40112 (parent: NOERROR)\n" {
		t.Errorf("rolled: %q", b.String())
	}
	b.Reset()
	if printRollResult(&b, 16282, 40112, answer(dns.RcodeRefused, 541, "at-apex: no KEY"), true, "update message failed", "") ||
		b.String() != "key 16282: roll refused by parent (EDE 541)\n  at-apex: no KEY\n" {
		t.Errorf("refused: %q", b.String())
	}
	b.Reset()
	printRollResult(&b, 16282, 0, tdns.UpdateResult{}, true, "zone child.example.: failed to sign message: no key", "")
	if b.String() != "key 16282: roll failed:\n  zone child.example.: failed to sign message: no key\n" {
		t.Errorf("local failure: %q", b.String())
	}
}

func TestInquireResult(t *testing.T) {
	var b bytes.Buffer
	printInquireResult(&b, 38310, "Trusted", true)
	printInquireResult(&b, 38310, "Auto Bootstrap Ongoing", false)
	want := "key 38310: trusted (authenticated)\nkey 38310: auto bootstrap ongoing (not authenticated)\n"
	if b.String() != want {
		t.Errorf("got %q, want %q", b.String(), want)
	}
}

// "parentsync sync" used to print one empty line whatever happened.
func TestSyncResult(t *testing.T) {
	ns := []string{"child.example.\t3600\tIN\tNS\tns2.child.example."}
	for _, tc := range []struct {
		name string
		dss  tdns.DelegationSyncStatus
		want string
		ok   bool
	}{
		{"in sync", inSync, "in sync; nothing sent\n", true},
		{"sent", tdns.DelegationSyncStatus{ZoneName: "child.example.", Scheme: "UPDATE", NsAddsStr: ns},
			"update sent to parent (NOERROR):\n  + NS    ns2.child.example.\n", true},
		{"notify", tdns.DelegationSyncStatus{ZoneName: "child.example.", Scheme: "NOTIFY", NsAddsStr: ns},
			"notify sent to parent:\n  + NS    ns2.child.example.\n", true},
		{"nothing sent", tdns.DelegationSyncStatus{ZoneName: "child.example.", NothingSent: true,
			Msg: "UPDATE skipped: waiting for the KEY at the primary\nNOTIFY skipped: parent does not advertise it"},
			"not in sync; nothing sent:\n  UPDATE skipped: waiting for the KEY at the primary\n" +
				"  NOTIFY skipped: parent does not advertise it\n", false},
		{"refused", tdns.DelegationSyncStatus{ZoneName: "child.example.", Scheme: "UPDATE", Error: true,
			ErrorMsg: "every available sync scheme failed", UpdateResult: answer(dns.RcodeRefused, 541, "key not trusted")},
			"update refused by parent (EDE 541):\n  key not trusted\n", false},
		{"failed", tdns.DelegationSyncStatus{ZoneName: "child.example.", Error: true, ErrorMsg: "no IMR"},
			"sync failed:\n  no IMR\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			ok := printSyncResult(&b, tc.dss)
			if b.String() != tc.want || ok != tc.ok {
				t.Errorf("got %q (%v), want %q (%v)", b.String(), ok, tc.want, tc.ok)
			}
		})
	}
}

func TestWrapLines(t *testing.T) {
	text := strings.Repeat("word ", 30)
	lines := wrapLines(text, "  label       ", "              ")
	if len(lines) < 2 {
		t.Fatalf("not wrapped: %q", lines)
	}
	fitsWidth(t, strings.Join(lines, "\n"))
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "              word") {
			t.Errorf("continuation not aligned: %q", l)
		}
	}
}

// proxy-key stays reachable where it was, hidden and marked deprecated.
func TestProxyKeyIsAHiddenDeprecatedAlias(t *testing.T) {
	for _, tc := range []struct {
		name string
		path []string
		root bool // AuthCmd, else AgentCmd
	}{
		{"auth zone proxy-key", []string{"zone", "proxy-key"}, true},
		{"agent zone proxy-key", []string{"zone", "proxy-key"}, false},
	} {
		root := AgentCmd
		if tc.root {
			root = AuthCmd
		}
		c := lookupCmd(root, tc.path...)
		if c == nil {
			t.Errorf("%s no longer resolves", tc.name)
			continue
		}
		if !c.Hidden {
			t.Errorf("%s is still advertised in help", tc.name)
		}
		if !strings.Contains(c.Deprecated, "parentsync status") {
			t.Errorf("%s: Deprecated = %q, want it to point at parentsync status", tc.name, c.Deprecated)
		}
		if strings.Contains(c.Long, "no key is generated") {
			t.Errorf("%s: the help text still claims no key is generated", tc.name)
		}
		if lookupCmd(root, "zone", "parentsync", "status") == nil {
			t.Errorf("%s: the command it points at does not exist", tc.name)
		}
	}
}
