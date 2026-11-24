/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// rootServerNames is the names of the servers under "." in the cache, sorted.
func rootServerNames(imr *Imr) []string {
	servers, _ := imr.Cache.ServerMapCopy(".")
	var names []string
	for _, s := range servers {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

// A configured "." stub is the root's servers. New installs it, and priming
// from the root hints at Start must not replace it with the hints' servers,
// nor may a reload that leaves the stub as it is. (When the stubs were
// installed after priming, the stub was the last word.)
func TestRootStubSurvivesPriming(t *testing.T) {
	restoreProcessWideTuning(t)
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if r.Question[0].Qtype == dns.TypeNS && r.Question[0].Name == "." {
			m.Answer = []dns.RR{mustRR(t, ". 518400 IN NS hints-root.test.")}
			m.Extra = []dns.RR{mustRR(t, "hints-root.test. 518400 IN A 127.0.0.1")}
		}
		_ = w.WriteMsg(m)
	})
	hints := filepath.Join(t.TempDir(), "root.hints")
	if err := os.WriteFile(hints, []byte(". 3600000 IN NS hints-root.test.\nhints-root.test. 3600000 IN A 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stub := StubConf{Zone: ".", Servers: []cache.AuthServer{{Name: "ns.private-root.test.", Addrs: []string{"192.0.2.53"}}}}
	ic := Config{RootHints: hints, Stubs: []StubConf{stub}, Options: map[Option]string{OptAllowLoopbackNameservers: "true"}}
	imr, err := New(context.Background(), ic, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	qminClients(imr, port)
	want := []string{"ns.private-root.test."}
	if got := rootServerNames(imr); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("after New the root's servers are %v, want the stub's %v", got, want)
	}

	if err := imr.primeFromHints(context.Background()); err != nil {
		t.Fatalf("priming: %v", err)
	}
	if got := rootServerNames(imr); len(got) != 1 || got[0] != want[0] {
		t.Errorf("after priming the root's servers are %v, want the stub's %v", got, want)
	}

	if _, err := imr.ReloadZones([]StubConf{stub}, nil); err != nil {
		t.Fatalf("ReloadZones: %v", err)
	}
	if got := rootServerNames(imr); len(got) != 1 || got[0] != want[0] {
		t.Errorf("after an unchanged reload the root's servers are %v, want the stub's %v", got, want)
	}
}
