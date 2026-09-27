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
)

func renderReport(r *tdns.ParentSyncReport, todo ...string) string {
	var b bytes.Buffer
	printParentSyncReport(&b, "child.example.", r, todo)
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

const proxyReadyText = "zone child.example.: UPDATE proxy READY — the agent's KEY is published at the apex and" +
	" the agent holds its private key.\n\nPublished at the primary's apex (for reference):\n\n" +
	"child.example.\t3600\tIN\tKEY\t256 3 15 abc=\n"

func TestParentSyncReportProxy(t *testing.T) {
	out := renderReport(&tdns.ParentSyncReport{
		Role:      "parentsync-proxy",
		Parent:    "example.",
		Validated: true,
		Schemes: []tdns.ParentSyncSchemeReport{
			{Scheme: "NOTIFY", Reason: "proxied zone publishes neither CDS nor CSYNC"},
			{Scheme: "UPDATE", Usable: true, Target: "update.example. port 53"},
		},
		Update:     &tdns.ParentSyncUpdateReport{ProxyReport: proxyReadyText},
		Notify:     &tdns.ParentSyncNotifyReport{Signed: true},
		Delegation: &tdns.DelegationSyncStatus{InSync: true, Parent: "example.", ZoneName: "child.example."},
	})

	mustAppearInOrder(t, out,
		"Zone child.example. (parentsync-proxy): parent example., DSYNC validated\n",
		"Schemes (in preference order):\n",
		"NOTIFY  skipped: proxied zone publishes neither CDS nor CSYNC\n",
		"UPDATE  usable:  update.example. port 53\n",
		proxyReadyText, // word for word, as proxy-key prints it
		"NOTIFY: the zone is signed; it publishes CDS: no, CSYNC: no\n",
		"Delegation: parent example. is in sync with child.example.\n",
	)
	if strings.Contains(out, "..") {
		t.Errorf("a name ending in a dot got a full stop after it:\n%s", out)
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
		Delegation: &tdns.DelegationSyncStatus{InSync: true, Parent: "example.", ZoneName: "child.example."},
	})
	for _, never := range []string{"SIG(0)", "KEY", "UPDATE"} {
		if strings.Contains(out, never) {
			t.Errorf("a NOTIFY-only report mentions %q:\n%s", never, out)
		}
	}
	if !strings.Contains(out, "it publishes CDS: yes, CSYNC: no") {
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
			ParentKeyState: "trusted", ParentKeyAuthenticated: true,
		},
		Delegation: &tdns.DelegationSyncStatus{InSync: true, Parent: "example.", ZoneName: "child.example."},
	}, "Add the zone's SIG(0) KEY record to child.example. at the primary server")

	mustAppearInOrder(t, out,
		"DSYNC NOT validated",
		"UPDATE: SIG(0) key 4711 is active and its KEY is published at the apex\n",
		"UPDATE: the parent's view of key 4711: trusted (authenticated)\n",
		"TODO:\n--> Add the zone's SIG(0) KEY",
	)

	out = renderReport(&tdns.ParentSyncReport{
		Role:   "parentsync",
		Update: &tdns.ParentSyncUpdateReport{ParentKeyError: "not asked: there is no active SIG(0) key"},
	})
	mustAppearInOrder(t, out,
		"UPDATE: the zone has no active SIG(0) key\n",
		"UPDATE: the parent's view of the key: not asked: there is no active SIG(0) key\n",
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
			DSAddsStr:   []string{"child.example.\t3600\tIN\tDS\t4711 15 2 ab"},
		},
		Warning: "DSYNC UPDATE proxy waiting: publish the KEY",
	})
	mustAppearInOrder(t, out,
		"Delegation: parent example. is NOT in sync with child.example.; changes needed:\n",
		"ADD NS", "ns2.child.example.",
		"DEL IPv4 GLUE", "192.0.2.1",
		"ADD DS", "4711 15 2 ab",
		"Warning (delegation-sync-warning): DSYNC UPDATE proxy waiting: publish the KEY\n",
	)
}

func TestParentSyncReportWhenThereIsNoPlan(t *testing.T) {
	out := renderReport(&tdns.ParentSyncReport{
		Role:            "parentsync-proxy",
		Parent:          "example.",
		PlanNote:        "no IMR available to discover the parent's DSYNC records",
		DelegationError: "delegation sync not available",
	})
	mustAppearInOrder(t, out,
		"Zone child.example. (parentsync-proxy): parent example.\n",
		"Schemes: none evaluated: no IMR available",
		"Delegation: could not compare with the parent: delegation sync not available\n",
	)
	if strings.Contains(out, "validated") {
		t.Errorf("a plan that looked at nothing reports on validation:\n%s", out)
	}

	out = renderReport(&tdns.ParentSyncReport{Role: "parentsync", PlanError: "DsyncDiscovery(child.example.): SERVFAIL"})
	mustAppearInOrder(t, out, "parent (unknown); DSYNC discovery failed: DsyncDiscovery(child.example.): SERVFAIL\n")
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

// The report words its own delegation verdict; "no action needed" belongs to
// the delta commands, whose sentence stays as it was.
func TestReportAndDeltaWordTheirVerdictsApart(t *testing.T) {
	inSync := tdns.DelegationSyncStatus{InSync: true, Parent: "example.", ZoneName: "child.example."}
	out := renderReport(&tdns.ParentSyncReport{
		Role:       "parentsync-proxy",
		Parent:     "example.",
		Update:     &tdns.ParentSyncUpdateReport{ProxyReport: "zone child.example.: UPDATE proxy WAITING — publish\n"},
		Delegation: &inSync,
	})
	if strings.Contains(out, "no action needed") {
		t.Errorf("the report says \"no action needed\" next to a publish instruction:\n%s", out)
	}

	var b bytes.Buffer
	printDelegationDelta(&b, inSync)
	if got, want := b.String(), "Delegation information in parent example. is in sync with child child.example.; no action needed.\n"; got != want {
		t.Errorf("parentsync delta changed:\n got %q\nwant %q", got, want)
	}
}

func TestDelegationChangeRowsIncludeDS(t *testing.T) {
	rows := delegationChangeRows(tdns.DelegationSyncStatus{
		DSAddsStr:    []string{"add"},
		DSRemovesStr: []string{"del"},
	})
	want := []string{"Change|RR", "ADD DS|add", "DEL DS|del"}
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Errorf("rows = %q, want %q", rows, want)
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
