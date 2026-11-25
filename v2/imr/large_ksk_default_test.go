/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"context"
	"testing"

	algorithms "github.com/johanix/tdns/v2/algorithms"
)

// Options.LargeAlgorithms nil is the default set, ML-DSA in it; an empty set
// is none. RefreshDnssecPolicy reads nil the same way.
func TestLargeAlgorithmsDefault(t *testing.T) {
	restoreProcessWideTuning(t)
	mldsa44, ok := algorithms.AlgorithmNumber("MLDSA44")
	if !ok {
		t.Fatal("MLDSA44 is not in the algorithm registry")
	}
	off := false
	ic := Config{}
	ic.Testing.Priming = &off

	imr, err := New(context.Background(), ic, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !imr.isLargeAlgorithm(mldsa44) {
		t.Error("with no LargeAlgorithms, ML-DSA-44 is not large")
	}
	if imr.isLargeAlgorithm(15) { // ED25519
		t.Error("with no LargeAlgorithms, ED25519 is large")
	}

	imr, err = New(context.Background(), ic, Options{LargeAlgorithms: map[uint8]bool{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if imr.isLargeAlgorithm(mldsa44) {
		t.Error("with an empty LargeAlgorithms, ML-DSA-44 is large")
	}
	imr.RefreshDnssecPolicy(nil, DNSKEYTransportUseDSSignal)
	if !imr.isLargeAlgorithm(mldsa44) {
		t.Error("after RefreshDnssecPolicy(nil), ML-DSA-44 is not large")
	}
}
