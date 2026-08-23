package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A non-regular file where the rejected-records artefact must go is an operator
// mistake, and has to be REPORTED rather than routed around.
//
// This used to be platform-dependent. os.ReadFile on a directory SUCCEEDS on
// NetBSD (read(2) on a directory fd returns raw dirent bytes) and FAILS on
// Linux and macOS, so the same directory either sent the artefact to a sibling
// name via freeArtefactPath, or fell through to a rename that could not
// succeed. TestAFailedMergeIsRetriedDespiteTheStatGate injects its failure by
// creating exactly such a directory, and therefore passed on one platform and
// failed on the other.
func TestRejectedArtefactRefusesANonRegularFile(t *testing.T) {
	dir := t.TempDir()
	zonefile := filepath.Join(dir, "example.zone")
	const serial = 100

	// Occupy the artefact path with a directory.
	artefact := zonefile + ".100.rejected"
	if err := os.Mkdir(artefact, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	insns := []ZoneDeltaRR{{Action: ZoneDeltaAdd, RR: "www.example. 3600 IN A 192.0.2.1"}}
	path, err := writeRejectedArtefactInstructions(zonefile, "example.", serial,
		ConflictDBWins, insns)
	if err == nil {
		t.Fatalf("writing the artefact succeeded (path %q) despite a directory in"+
			" the way; on NetBSD this silently diverted to a sibling name", path)
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("error does not name the cause: %v", err)
	}

	// And nothing was written beside it.
	if entries, derr := filepath.Glob(zonefile + ".100.rejected.*"); derr == nil && len(entries) > 0 {
		t.Errorf("artefact was diverted to %v instead of being refused", entries)
	}
}

// The retry path must still work: rewriting identical content over an existing
// REGULAR artefact is allowed and returns the same path.
func TestRejectedArtefactRewritesIdenticalContent(t *testing.T) {
	dir := t.TempDir()
	zonefile := filepath.Join(dir, "example.zone")
	insns := []ZoneDeltaRR{{Action: ZoneDeltaAdd, RR: "www.example. 3600 IN A 192.0.2.1"}}

	first, err := writeRejectedArtefactInstructions(zonefile, "example.", 100,
		ConflictDBWins, insns)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	second, err := writeRejectedArtefactInstructions(zonefile, "example.", 100,
		ConflictDBWins, insns)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if first != second {
		t.Errorf("identical content was written to a new path (%q then %q);"+
			" the retry would leave a trail of duplicates", first, second)
	}
}
