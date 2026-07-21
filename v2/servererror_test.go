/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestServerErrors_SetClearList(t *testing.T) {
	r := NewServerErrorRegistry()
	if r.HasAny() || len(r.List()) != 0 {
		t.Fatal("fresh registry must be empty")
	}

	r.SetTransportCertError("cert gone")
	if !r.HasAny() || len(r.List()) != 1 {
		t.Fatalf("expected 1 error, got %d", len(r.List()))
	}
	e := r.List()[0]
	if e.Category != ErrCatTransport || e.Subtype != ErrSubCert || e.Message != "cert gone" {
		t.Fatalf("wrong error recorded: %s", e)
	}
	if e.FirstSeen.IsZero() || e.LastSeen.IsZero() {
		t.Fatal("timestamps not set")
	}

	// Re-setting the same class updates the message, does not stack.
	r.SetTransportCertError("still gone")
	if len(r.List()) != 1 || r.List()[0].Message != "still gone" {
		t.Fatalf("re-set should update in place: %v", r.List())
	}

	// A distinct class only clears itself.
	r.SetConfigCertMissing("file missing")
	if len(r.List()) != 2 {
		t.Fatalf("expected 2 classes, got %d", len(r.List()))
	}
	r.ClearTransportCertError()
	got := r.List()
	if len(got) != 1 || got[0].Subtype != ErrSubCertMissing {
		t.Fatalf("clearing Cert must leave only CertMissing: %v", got)
	}
	r.ClearConfigCertMissing()
	if r.HasAny() {
		t.Fatal("registry should be empty after clearing all")
	}
}

func TestServerErrors_PortAggregation(t *testing.T) {
	r := NewServerErrorRegistry()
	r.SetTransportPortError("dot 127.0.0.1:853", errors.New("permission denied"))
	r.SetTransportPortError("doh 127.0.0.1:443", errors.New("permission denied"))
	// Same class, aggregated into one entry naming both listeners.
	list := r.List()
	if len(list) != 1 || list[0].Subtype != ErrSubPort {
		t.Fatalf("expected a single aggregated Port error, got %v", list)
	}
	if !strings.Contains(list[0].Message, "853") || !strings.Contains(list[0].Message, "443") {
		t.Fatalf("aggregated message should name both listeners: %q", list[0].Message)
	}
	// A repeat of the same hostport does not duplicate.
	before := list[0].Message
	r.SetTransportPortError("dot 127.0.0.1:853", errors.New("permission denied"))
	if r.List()[0].Message != before {
		t.Fatalf("repeat of same listener should not change message: %q -> %q", before, r.List()[0].Message)
	}
}

func TestServerErrors_ListSorted(t *testing.T) {
	r := NewServerErrorRegistry()
	r.SetConfigCertMissing("c") // Config category
	r.SetTransportPortError("dot x", errors.New("p"))
	r.SetTransportCertError("cert")
	list := r.List()
	// Transport (1) before Config (2); within Transport, Cert (1) before Port (2).
	if len(list) != 3 {
		t.Fatalf("expected 3, got %d", len(list))
	}
	want := []struct {
		cat ErrorCategory
		sub ErrorSubtype
	}{
		{ErrCatTransport, ErrSubCert},
		{ErrCatTransport, ErrSubPort},
		{ErrCatConfig, ErrSubCertMissing},
	}
	for i, w := range want {
		if list[i].Category != w.cat || list[i].Subtype != w.sub {
			t.Fatalf("sort order wrong at %d: got %s", i, list[i])
		}
	}
}

func TestServerErrors_NilSafe(t *testing.T) {
	var r *ServerErrorRegistry // nil, e.g. before init
	r.SetTransportCertError("x")
	r.SetTransportPortError("h", errors.New("e"))
	r.ClearConfigCertMissing()
	if r.HasAny() || r.List() != nil {
		t.Fatal("nil registry must be a safe no-op")
	}
}

func TestServerErrors_ValidateDnsEngineCerts(t *testing.T) {
	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()

	// No encrypted transports: no cert error even with empty cert paths.
	conf.DnsEngine.Transports = []string{"do53"}
	conf.validateDnsEngineCerts()
	if conf.Internal.ServerErrors.HasAny() {
		t.Fatal("do53-only must not produce a CertMissing error")
	}

	// Encrypted transport + missing files: Config/CertMissing set.
	conf.DnsEngine.Transports = []string{"do53", "dot"}
	conf.DnsEngine.CertFile = "/nonexistent/x.crt"
	conf.DnsEngine.KeyFile = "/nonexistent/x.key"
	conf.validateDnsEngineCerts()
	list := conf.Internal.ServerErrors.List()
	if len(list) != 1 || list[0].Category != ErrCatConfig || list[0].Subtype != ErrSubCertMissing {
		t.Fatalf("expected Config/CertMissing, got %v", list)
	}

	// Files now present + clear-then-reassert on the next validate: cleared.
	crt, _ := os.CreateTemp(t.TempDir(), "x*.crt")
	key, _ := os.CreateTemp(t.TempDir(), "x*.key")
	conf.DnsEngine.CertFile = crt.Name()
	conf.DnsEngine.KeyFile = key.Name()
	conf.validateDnsEngineCerts()
	if conf.Internal.ServerErrors.HasAny() {
		t.Fatalf("CertMissing must clear once files exist: %v", conf.Internal.ServerErrors.List())
	}
}
