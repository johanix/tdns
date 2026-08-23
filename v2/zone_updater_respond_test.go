/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Phase 2 gave UpdateRequest a reply channel and made the RFC 2136 responder
// wait on it: a NOERROR is a promise, so it is not sent until the change is
// applied, persisted and published. The responder queues with dur.Status.Type
// as the command, and that is "CHILD-UPDATE" or "TRUSTSTORE-UPDATE" as often as
// it is "ZONE-UPDATE".
//
// So every branch of the updater's command switch has to answer. A branch that
// does not costs its caller a full UpdateApplyTimeout of silence and then a
// SERVFAIL -- for an update that succeeded. That was the state of the
// CHILD-UPDATE branch, which is the one the entire DSYNC UPDATE scheme runs
// through, and of TRUSTSTORE-UPDATE, which is SIG(0) key upload.
//
// Checked by reading the source rather than by driving the updater: the
// branches need a live KeyDB, a delegation backend and a running goroutine to
// exercise, and the property being defended is structural. A new command added
// without a respond() call fails here, which is the point.
func TestEveryUpdaterCommandAnswersTheReplyChannel(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "zone_updater.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing zone_updater.go: %v", err)
	}

	var switches []*ast.TypeSwitchStmt // unused, but keeps the intent explicit
	_ = switches

	found := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || sw.Tag == nil {
			return true
		}
		// The command switch is the one whose tag is ur.Cmd.
		sel, ok := sw.Tag.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Cmd" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			name := "default"
			if len(cc.List) > 0 {
				if lit, ok := cc.List[0].(*ast.BasicLit); ok {
					name = strings.Trim(lit.Value, `"`)
				}
			}
			found[name] = caseCallsRespond(cc)
		}
		return true
	})

	if len(found) == 0 {
		t.Fatal("could not find the ur.Cmd switch in zone_updater.go; this test needs updating")
	}
	// The commands that existed when this was written. A missing one means the
	// switch was restructured and this test is no longer checking what it
	// claims to check.
	for _, want := range []string{"CHILD-UPDATE", "ZONE-UPDATE", "TRUSTSTORE-UPDATE", "default"} {
		if _, ok := found[want]; !ok {
			t.Errorf("no %q case found in the ur.Cmd switch; test needs updating", want)
		}
	}
	for cmd, answers := range found {
		if !answers {
			t.Errorf("the %q branch never calls ur.respond(): a caller waiting on Resp"+
				" will block for UpdateApplyTimeout and then report failure for an"+
				" update that may have succeeded", cmd)
		}
	}
}

func caseCallsRespond(cc *ast.CaseClause) bool {
	var calls bool
	for _, stmt := range cc.Body {
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "respond" {
				calls = true
			}
			return true
		})
	}
	return calls
}
