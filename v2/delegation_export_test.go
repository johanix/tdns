/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// exportReply is the /delegation reply as it crosses the wire, decoded by
// key: what a client of the export command reads.
type exportReply struct {
	Error    bool
	ErrorMsg string
	Export   string
}

func postDelegationExport(t *testing.T, dp DelegationPost) exportReply {
	t.Helper()
	body, _ := json.Marshal(dp)
	rec := httptest.NewRecorder()
	APIdelegation(nil)(rec, httptest.NewRequest(http.MethodPost, "/delegation", bytes.NewReader(body)))
	var r exportReply
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return r
}

// noFilesIn fails the test if dir holds anything.
func noFilesIn(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		t.Errorf("the daemon wrote %s", filepath.Join(dir, e.Name()))
	}
}

// Export is a read: the delegation data comes back in the reply, as the
// zone-file fragment the parent holds, and nothing is written. The working
// directory is an empty one, so that a relative write would show.
func TestDelegationExportReturnsTheData(t *testing.T) {
	delegationParent(t)
	cwd := t.TempDir()
	t.Chdir(cwd)

	r := postDelegationExport(t, DelegationPost{Command: "export", Zone: "parent.example."})
	if r.Error {
		t.Fatalf("export refused: %s", r.ErrorMsg)
	}
	for _, want := range []string{
		"; Delegation data for parent zone parent.example.\n",
		"; Children: 2\n",
		"; --- alpha.parent.example. ---\n",
		"alpha.parent.example.\t3600\tIN\tNS\tns.alpha.parent.example.\n",
		"ns.alpha.parent.example.\t3600\tIN\tA\t192.0.2.51\n",
		"ns.alpha.parent.example.\t3600\tIN\tAAAA\t2001:db8::51\n",
		"bravo.parent.example.\t3600\tIN\tNS\tns.bravo.parent.example.\n",
	} {
		if !strings.Contains(r.Export, want) {
			t.Errorf("export lacks %q; got:\n%s", want, r.Export)
		}
	}
	noFilesIn(t, cwd)
}

// The daemon never writes a file at a path from the request. Export needs
// only the read-only role, and the file was written as the daemon's user:
// any read-only client could replace any file the daemon could write.
// A request that still names one is refused, and nothing is written there,
// next to it, or in the daemon's working directory.
func TestDelegationExportRefusesAnOutfile(t *testing.T) {
	delegationParent(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	target := t.TempDir()

	for _, outfile := range []string{filepath.Join(target, "victim"), "relative-victim"} {
		r := postDelegationExport(t, DelegationPost{Command: "export", Zone: "parent.example.", Outfile: outfile})
		if !r.Error || !strings.Contains(r.ErrorMsg, "outfile refused") {
			t.Errorf("outfile %q: error=%v %q, want the outfile refused", outfile, r.Error, r.ErrorMsg)
		}
		if r.Export != "" {
			t.Errorf("outfile %q: a refused request returned data", outfile)
		}
	}
	noFilesIn(t, target)
	noFilesIn(t, cwd)
}
