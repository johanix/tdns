package debug

import (
	"errors"
	"testing"
)

func TestClassifyCommandProbe(t *testing.T) {
	cases := []struct {
		name       string
		httpStatus int
		err        error
		respError  bool
		errorMsg   string
		want       CapStatus
	}{
		{"transport error", 0, errors.New("connection refused"), false, "", CapAbsent},
		{"endpoint 404", 404, nil, false, "", CapAbsent},
		{"http 500", 500, nil, false, "", CapAbsent},
		{"unknown zone command", 200, nil, true, "Unknown zone command: bump", CapAbsent},
		{"unknown debug command", 200, nil, true, "Unknown command: zone-txlog", CapAbsent},
		// The crucial distinction: an error about the probe zone (not about
		// the command) proves the command is routed → available.
		{"zone not found", 200, nil, true, "zone _tdns-debug-probe.invalid. is not known", CapAvailable},
		{"clean success", 200, nil, false, "", CapAvailable},
	}
	for _, c := range cases {
		got, _ := ClassifyCommandProbe(c.httpStatus, c.err, c.respError, c.errorMsg)
		if got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestCapabilityMatrixGating(t *testing.T) {
	m := &CapabilityMatrix{Target: "unit"}
	m.set(CapApi, CapAvailable, "")
	m.set(CapDebugTxlog, CapAbsent, "Unknown command: zone-txlog")

	if !m.Available(CapApi) {
		t.Errorf("CapApi should be available")
	}
	if m.Available(CapDebugTxlog) {
		t.Errorf("CapDebugTxlog should not be available")
	}
	// CapNone (pure DNS actors) is always available regardless of matrix.
	if !m.Available(CapNone) {
		t.Errorf("CapNone must always be available")
	}
	// Unknown capability is not available (fail closed).
	if m.Available("no-such-cap") {
		t.Errorf("unknown capability must not be available")
	}

	m.Degrade(CapApi, "mid-run failure")
	if m.Available(CapApi) {
		t.Errorf("degraded capability must not count as available")
	}
	if m.Get(CapApi) != CapDegraded {
		t.Errorf("Get after Degrade: got %s", m.Get(CapApi))
	}
}

func TestMarkerRR(t *testing.T) {
	rr := MarkerRR("test001.test.example.", "test001")
	want := `_tdns-debug.test001.test.example. 3600 IN TXT "test-id=test001"`
	if rr != want {
		t.Errorf("MarkerRR:\n got %q\nwant %q", rr, want)
	}
}
