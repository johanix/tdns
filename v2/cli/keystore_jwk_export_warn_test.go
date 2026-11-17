/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The warnings a JWK export prints: keys left out by --skip-unsupported,
 * and keys whose algorithm number is the dnssec-algorithms registry's.
 */
package cli

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2"
)

func TestBulkSkippedWarnsPerKeyAndSummarises(t *testing.T) {
	skipped := []tdns.BulkSkippedKey{
		{Zone: "a.example.", Keyid: 111, Algorithm: "MLDSA44", Reason: "stored without its seed"},
		{Zone: "b.example.", Keyid: 222, Algorithm: "ECCGOST", Reason: "no JWK form"},
	}
	var w bytes.Buffer
	printBulkSkipped(&w, skipped)
	printBulkSkippedSummary(&w, skipped)
	lines := strings.Split(strings.TrimSuffix(w.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want one line per key plus a summary, got %q", w.String())
	}
	for i, k := range skipped {
		for _, want := range []string{"WARNING", k.Zone, "keyid " + strconv.Itoa(int(k.Keyid)), k.Algorithm, k.Reason, "NOT written"} {
			if !strings.Contains(lines[i], want) {
				t.Errorf("line %q lacks %q", lines[i], want)
			}
		}
	}
	if !strings.Contains(lines[2], "WARNING: 2 key(s) NOT written") {
		t.Errorf("summary = %q", lines[2])
	}

	w.Reset()
	printBulkSkipped(&w, nil)
	printBulkSkippedSummary(&w, nil)
	if w.Len() != 0 {
		t.Errorf("nothing skipped must print nothing, got %q", w.String())
	}
}

func TestWarnRegistryOnlyAlgorithm(t *testing.T) {
	const pub = "AwEAAQ=="
	for rr, wantNote := range map[string]bool{
		"pq.example. 3600 IN DNSKEY 257 3 200 " + pub: true,
		"pq.example. 3600 IN DNSKEY 257 3 201 " + pub: true,
		"pq.example. 3600 IN KEY 256 3 201 " + pub:    true,
		"pq.example. 3600 IN DNSKEY 257 3 18 " + pub:  false,
		"pq.example. 3600 IN DNSKEY 257 3 15 " + pub:  false,
	} {
		var w bytes.Buffer
		warnRegistryOnlyAlgorithm(&w, "pq.example.", 4711, rr)
		got := w.String()
		if !wantNote {
			if got != "" {
				t.Errorf("%s: unexpected warning %q", rr, got)
			}
			continue
		}
		for _, want := range []string{"WARNING: pq.example. keyid 4711:", "dnssec-algorithms registry", "IANA"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: warning %q lacks %q", rr, got, want)
			}
		}
	}
}
