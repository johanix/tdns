package cli

import (
	"testing"

	"github.com/johanix/tdns/v2"
)

func TestReloadTsigWithheld(t *testing.T) {
	if !reloadTsigWithheld(tdns.ConfigResponse{TsigConflicts: []string{"k."}}) {
		t.Fatal("expected withheld on conflicts")
	}
	if !reloadTsigWithheld(tdns.ConfigResponse{TsigWithheldRemovals: []string{"k."}}) {
		t.Fatal("expected withheld on removals")
	}
	if reloadTsigWithheld(tdns.ConfigResponse{}) {
		t.Fatal("expected clean reload")
	}
}

func TestTsigImportConflictCount(t *testing.T) {
	if n := tsigImportConflictCount([]tdns.TsigKeyDisposition{
		{Name: "a.", Status: "imported"},
		{Name: "b.", Status: "conflict"},
		{Name: "c.", Status: "conflict"},
	}); n != 2 {
		t.Fatalf("got %d", n)
	}
}

func TestTsigForceInteractiveExclusive(t *testing.T) {
	if !tsigForceInteractiveConflict(true, true) {
		t.Fatal("expected conflict")
	}
	if tsigForceInteractiveConflict(true, false) {
		t.Fatal("unexpected conflict")
	}
}
