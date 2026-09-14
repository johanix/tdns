package tdns

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// T1a.5, the single-writer gate: every INSERT into DnssecKeyStore and every
// UPDATE of its state in this package's non-test code lives in setKeyRowTx or
// insertKeyRowTx (design §3.2). A write anywhere else leaves pub and sign
// stale, which is exactly what the columns must never be.
//
// This scans source, so it holds for code that no test exercises.
func TestKeystoreStateWritesLiveInTheOneWriteFunction(t *testing.T) {
	allowed := map[string]string{
		"setKeyRowTx":    "the one UPDATE of state",
		"insertKeyRowTx": "the one INSERT",
		// The data migrations run before the flag backfill that follows them
		// in the same open, so a state they rewrite gets its flags derived
		// again; they cannot use the write function, which needs a KeyDB.
		"dbMigrateData": "runs before the backfill",
	}
	insertRe := regexp.MustCompile(`(?i)INSERT\s+(?:OR\s+\w+\s+)?INTO\s+DnssecKeyStore\b`)
	updateRe := regexp.MustCompile(`(?i)UPDATE\s+DnssecKeyStore\s+SET\b`)
	stateRe := regexp.MustCompile(`(?i)\bstate\s*=`)

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var found int
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var hits []int
		for _, m := range insertRe.FindAllIndex(src, -1) {
			hits = append(hits, m[0])
		}
		for _, m := range updateRe.FindAllIndex(src, -1) {
			// The SET clause: up to WHERE, or the end of the string literal.
			rest := src[m[1]:]
			end := len(rest)
			for _, stop := range []string{"WHERE", "where", "`", `"`} {
				if i := strings.Index(string(rest), stop); i >= 0 && i < end {
					end = i
				}
			}
			if stateRe.Match(rest[:end]) {
				hits = append(hits, m[0])
			}
		}
		if len(hits) == 0 {
			continue
		}
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		tf := fset.File(af.Pos())
		for _, off := range hits {
			found++
			pos := tf.Pos(off)
			fn := enclosingFuncName(af, pos)
			if _, ok := allowed[fn]; ok {
				continue
			}
			where := fn
			if where == "" {
				where = "package scope"
			}
			t.Errorf("%s: a DnssecKeyStore write outside the write functions, in %s; route it through setKeyRowTx or insertKeyRowTx", fset.Position(pos), where)
		}
	}
	if found == 0 {
		t.Fatal("no keystore write found at all; the scan is broken")
	}
}

func enclosingFuncName(af *ast.File, pos token.Pos) string {
	for _, d := range af.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || pos < fd.Pos() || pos >= fd.End() {
			continue
		}
		return fd.Name.Name
	}
	return ""
}

// The other half of T1a.5: a test keystore refuses a state update that
// leaves pub or sign unset, so a raw UPDATE cannot slip through a test.
func TestTestKeystoreRefusesAStateUpdateThatLeavesFlagsUnset(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "guard.example."
	keyid := insertTestKeyRow(t, kdb, zone, DnskeyStateStandby, "ZSK", newTestRand(8))
	_, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET state=?, pub=NULL WHERE zonename=? AND keyid=?`, DnskeyStateActive, zone, keyid)
	if err == nil {
		t.Fatal("a state update that unset pub was accepted")
	}
	if !strings.Contains(err.Error(), "left pub or sign unset") {
		t.Errorf("unexpected refusal: %v", err)
	}
	var state string
	if err := kdb.DB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, keyid).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != DnskeyStateStandby {
		t.Errorf("the refused update changed the state to %q", state)
	}
}
