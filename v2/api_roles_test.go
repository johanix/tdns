package tdns

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestApiRoleTableMatchesTheHandlers holds apiRouteRoles to the code. It parses
// this package, finds every route the two router builders register and the
// handler each one calls, and collects the command strings each handler
// switches on (switch x.Command). Then:
//
//   - every registered route must have an entry in the table;
//   - every command a handler knows must be listed for its route, unless the
//     route is admin for everything ("*": admin) -- so a new command is a
//     decision, not an accident of the default;
//   - a non-admin "*" is allowed only on a route whose handler has no command
//     switch at all (it then means "this route");
//   - every command listed must still exist in its handler.
func TestApiRoleTableMatchesTheHandlers(t *testing.T) {
	routes, funcs := parseApiRoutes(t)

	for route, handler := range routes {
		table, ok := apiRouteRoles[route]
		if !ok {
			t.Errorf("route %s (%s) has no entry in apiRouteRoles: decide its roles", route, handler)
			continue
		}
		fd := funcs[handler]
		if fd == nil {
			t.Errorf("route %s: handler %s not found", route, handler)
			continue
		}
		cmds := commandsOf(fd)
		star, hasStar := table["*"]
		allAdmin := hasStar && star == RoleAdmin
		if hasStar && !allAdmin && len(cmds) > 0 {
			t.Errorf("route %s: a non-admin \"*\" on a handler with commands %v; list them instead", route, cmds)
		}
		for _, c := range cmds {
			if _, ok := table[c]; !ok && !allAdmin {
				t.Errorf("route %s: command %q (in %s) is not in apiRouteRoles; decide its role", route, c, handler)
			}
		}
		known := map[string]bool{}
		for _, c := range cmds {
			known[c] = true
		}
		for c := range table {
			if c != "" && c != "*" && !known[c] {
				t.Errorf("route %s: apiRouteRoles lists %q, which %s no longer has", route, c, handler)
			}
		}
	}
	for route := range apiRouteRoles {
		if _, ok := routes[route]; !ok {
			t.Errorf("apiRouteRoles has %s, which no router builder registers", route)
		}
	}
}

// parseApiRoutes parses this package and returns every route the two router
// builders register with the name of the handler each one calls, and the
// package's functions by name.
func parseApiRoutes(t *testing.T) (map[string]string, map[string]*ast.FuncDecl) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok {
					funcs[fd.Name.Name] = fd
				}
			}
		}
	}

	// route -> handler function name, from the builders' sr.HandleFunc calls.
	routes := map[string]string{}
	for _, builder := range []string{"SetupAPIRouter", "SetupSimpleAPIRouter"} {
		fd := funcs[builder]
		if fd == nil {
			t.Fatalf("router builder %s not found", builder)
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "HandleFunc" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				return true
			}
			path, _ := strconv.Unquote(lit.Value)
			h, ok := call.Args[1].(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := h.Fun.(type) {
			case *ast.Ident:
				routes["/api/v1"+path] = fn.Name
			case *ast.SelectorExpr:
				routes["/api/v1"+path] = fn.Sel.Name
			}
			return true
		})
	}
	if len(routes) < 10 {
		t.Fatalf("found only %d routes; the parse is broken: %v", len(routes), routes)
	}

	return routes, funcs
}

// commandsOf collects the string cases of every switch in fd whose tag reads a
// field named Command, lower-cased and trimmed as RequiredApiRole does.
func commandsOf(fd *ast.FuncDecl) []string {
	seen := map[string]bool{}
	ast.Inspect(fd, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || sw.Tag == nil || !readsCommand(sw.Tag) {
			return true
		}
		for _, st := range sw.Body.List {
			cc, ok := st.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, e := range cc.List {
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					s, _ := strconv.Unquote(lit.Value)
					seen[strings.ToLower(strings.TrimSpace(s))] = true
				}
			}
		}
		return true
	})
	var out []string
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func readsCommand(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Command" {
			found = true
		}
		return !found
	})
	return found
}
