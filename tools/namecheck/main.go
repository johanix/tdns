package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// foldFuncs classifies the functions that turn a domain name into a folded
// form. "safe" ones fold by the DNS rule: US-ASCII A-Z and nothing else, octet
// for octet. The rest lose information a name may carry.
var foldFuncs = map[string]string{
	// The DNS rule. core.CanonicalizeName and the thin wrappers over it.
	"core.CanonicalizeName": "safe",
	"CanonicalizeName":      "safe",
	"ServerKey":             "safe",
	"nk":                    "safe",
	"rrsetKey":              "safe",
	"dnskeyKey":             "safe",
	"zoneKey":               "safe",

	// Correct about case, but rewrites every octet that is not valid UTF-8
	// into U+FFFD, so two distinct names collide on one key.
	"dns.CanonicalName": "lossy-utf8",

	// Unicode simple case folding: U+212A KELVIN SIGN becomes "k", U+017F
	// LATIN SMALL LETTER LONG S becomes "s". RFC 4343 folds neither.
	"strings.ToLower": "unicode",
	"strings.ToUpper": "unicode",
	"lc":              "unicode",
}

// nameish is the heuristic for "this identifier holds a domain name". Used only
// by the namecmp check, which is advisory; keyfold and foldpair are structural
// and do not guess.
var nameish = []string{
	"qname", "ownername", "owner", "zonename", "zname", "apex", "signername",
	"nsname", "childname", "child", "parent", "domain", "fqdn", "basename",
}

type finding struct {
	pos   token.Position
	check string
	msg   string
}

type reporter struct {
	fset     *token.FileSet
	allow    map[string]bool
	findings []finding
	root     string
}

func (r *reporter) report(check string, pos token.Pos, format string, args ...any) {
	p := r.fset.Position(pos)
	rel, err := filepath.Rel(r.root, p.Filename)
	if err == nil {
		p.Filename = rel
	}
	if r.allow[fmt.Sprintf("%s:%d", p.Filename, p.Line)] {
		return
	}
	r.findings = append(r.findings, finding{pos: p, check: check, msg: fmt.Sprintf(format, args...)})
}

// callName renders a call's function as "pkg.Func" or "Func", or "" if it is
// not a plain identifier or selector.
func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok {
			return x.Name + "." + fn.Sel.Name
		}
	}
	return ""
}

// foldOf reports the fold classification of an expression, looking through one
// level of wrapping: CanonicalizeName(dns.Fqdn(x)) is still a fold, and so is
// dns.Fqdn(strings.ToLower(x)).
func foldOf(e ast.Expr) (fn, class string) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return "", ""
	}
	name := callName(call)
	if c, ok := foldFuncs[name]; ok {
		return name, c
	}
	// A transparent wrapper: recurse into its first argument.
	if name == "dns.Fqdn" || name == "strings.TrimSpace" || name == "strings.TrimSuffix" {
		if len(call.Args) > 0 {
			return foldOf(call.Args[0])
		}
	}
	return "", ""
}

func looksLikeName(e ast.Expr) bool {
	var s string
	switch v := e.(type) {
	case *ast.Ident:
		s = v.Name
	case *ast.SelectorExpr:
		s = v.Sel.Name
	case *ast.CallExpr:
		n := callName(v)
		if n == "dns.Fqdn" || n == "dns.CanonicalName" {
			return true
		}
		if strings.HasSuffix(n, ".Name") {
			return true
		}
		return false
	default:
		return false
	}
	l := strings.ToLower(s)
	for _, w := range nameish {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- keyfold
//
// A map key built by a lossy fold. Catches the ZONEMD groupByOwner collision
// and the config-check store/lookup split directly, and does it without
// guessing whether anything is a "name": if a value is folded at all, it is a
// name, and if it is then used as a map key the fold has to be the safe one.
func (r *reporter) checkKeyFold(file *ast.File) {
	// A function whose body is `return <fold>(name)` is manufacturing a key even
	// though no map is in sight -- zoneNameKey, canonDsyncApiUser, the rollover
	// lock key. Reverting one of those to strings.ToLower is invisible to a
	// check that only looks at index expressions, which is how the #417
	// near-miss got past the first draft of this tool.
	ast.Inspect(file, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		fn, class := foldOf(ret.Results[0])
		if class == "" || class == "safe" {
			return true
		}
		if class != "lossy-utf8" && !foldedValueIsName(ret.Results[0]) {
			return true
		}
		r.report("keyfold", ret.Results[0].Pos(),
			"a name folded with %s is returned as a key: %s", fn, whyLossy(class))
		return true
	})

	// A local folded once and then used to index a map: the fold and the index
	// are two statements apart, so the index-expression check below cannot see
	// it.
	ast.Inspect(file, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			return true
		}
		bad := map[string]string{} // local -> fold func
		ast.Inspect(fd.Body, func(m ast.Node) bool {
			as, ok := m.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			id, ok := as.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			fn, class := foldOf(as.Rhs[0])
			if class == "" || class == "safe" {
				return true
			}
			if class != "lossy-utf8" && !foldedValueIsName(as.Rhs[0]) {
				return true
			}
			bad[id.Name] = fn + "\x00" + class
			return true
		})
		if len(bad) == 0 {
			return true
		}
		ast.Inspect(fd.Body, func(m ast.Node) bool {
			idx, ok := m.(*ast.IndexExpr)
			if !ok {
				return true
			}
			id, ok := idx.Index.(*ast.Ident)
			if !ok {
				return true
			}
			if enc, isBad := bad[id.Name]; isBad {
				fn, class, _ := strings.Cut(enc, "\x00")
				r.report("keyfold", idx.Index.Pos(),
					"map key %s was folded with %s further up: %s", id.Name, fn, whyLossy(class))
			}
			return true
		})
		return true
	})

	ast.Inspect(file, func(n ast.Node) bool {
		idx, ok := n.(*ast.IndexExpr)
		if !ok {
			return true
		}
		fn, class := foldOf(idx.Index)
		if class == "" || class == "safe" {
			return true
		}
		// dns.CanonicalName is BY DEFINITION applied to a domain name, so a key
		// built from it is always in scope. strings.ToLower/ToUpper are
		// general-purpose -- upper-casing an algorithm name or a config
		// identifier is fine -- so those need a reason to believe the value is
		// a name: either it looks like one, or it has been through dns.Fqdn.
		if class != "lossy-utf8" && !foldedValueIsName(idx.Index) {
			return true
		}
		r.report("keyfold", idx.Index.Pos(),
			"map key built with %s, which %s", fn, whyLossy(class))
		return true
	})
}

func whyLossy(class string) string {
	if class == "lossy-utf8" {
		return "rewrites non-UTF-8 octets to U+FFFD, so two distinct names share " +
			"one key; use core.CanonicalizeName"
	}
	return "folds by Unicode (U+212A KELVIN SIGN collides with \"k\"), so two " +
		"distinct names share one key; use core.CanonicalizeName"
}

// foldedValueIsName reports whether a folded expression is a domain name rather
// than an identifier that merely happens to be case-folded. Passing through
// dns.Fqdn is conclusive; otherwise fall back to the name heuristic.
func foldedValueIsName(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	if callName(call) == "dns.Fqdn" {
		return true
	}
	for _, a := range call.Args {
		if inner, ok := a.(*ast.CallExpr); ok && callName(inner) == "dns.Fqdn" {
			return true
		}
		if looksLikeName(a) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- namecmp
//
// Comparing domain names with the wrong tool. Advisory: it uses the name
// heuristic, so it is the check most likely to want an allowlist entry.
func (r *reporter) checkNameCmp(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		switch callName(call) {
		case "strings.EqualFold":
			if looksLikeName(call.Args[0]) || looksLikeName(call.Args[1]) {
				r.report("namecmp", call.Pos(),
					"strings.EqualFold on what looks like a domain name: it folds by "+
						"Unicode, RFC 4343 folds US-ASCII A-Z only; use core.EqualNames")
			}
		case "strings.HasSuffix":
			if looksLikeName(call.Args[0]) && looksLikeName(call.Args[1]) {
				r.report("namecmp", call.Pos(),
					"strings.HasSuffix between two domain names is not a bailiwick test: "+
						"it matches across a label boundary (\"ns.evilexample.\" ends with "+
						"\"example.\"); use dns.IsSubDomain")
			}
		}
		return true
	})
}

// ---------------------------------------------------------------- foldpair
//
// The "_dns." bug: a value tested through a fold and then acted on unfolded,
// inside one function. Structural, no name heuristic.
func (r *reporter) checkFoldPair(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		// subject -> literal it was tested against, through a fold
		tested := map[string]string{}
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			name := callName(call)
			if name != "strings.HasPrefix" && name != "strings.HasSuffix" {
				return true
			}
			if _, class := foldOf(call.Args[0]); class == "" {
				return true
			}
			subj := innerSubject(call.Args[0])
			if subj != "" {
				tested[subj] = exprText(call.Args[1])
			}
			return true
		})
		if len(tested) == 0 {
			return true
		}
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			name := callName(call)
			if name != "strings.TrimPrefix" && name != "strings.TrimSuffix" {
				return true
			}
			subj, ok := call.Args[0].(*ast.Ident)
			if !ok {
				return true
			}
			lit, seen := tested[subj.Name]
			if !seen || lit != exprText(call.Args[1]) {
				return true
			}
			r.report("foldpair", call.Pos(),
				"%s is tested through a fold and then trimmed unfolded: the test "+
					"accepts a spelling the trim will not strip, leaving the affix in "+
					"place; slice by len(%s) instead", subj.Name, lit)
			return true
		})
		return true
	})
}

// innerSubject digs out the identifier a fold was applied to.
func innerSubject(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.CallExpr:
		if len(v.Args) > 0 {
			return innerSubject(v.Args[0])
		}
	}
	return ""
}

func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Value
	case *ast.Ident:
		return v.Name
	}
	return ""
}

func loadAllow(path string) (map[string]bool, error) {
	out := map[string]bool{}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for ln := 1; sc.Scan(); ln++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "path:line: reason" -- the reason is required, so an entry has to
		// say why it is there.
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || strings.TrimSpace(parts[2]) == "" {
			return nil, fmt.Errorf("%s:%d: want \"path:line: reason\", got %q", path, ln, line)
		}
		out[parts[0]+":"+parts[1]] = true
	}
	return out, sc.Err()
}

func main() {
	allowPath := flag.String("allow", "", "allowlist file of \"path:line: reason\" entries")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: namecheck [-allow FILE] DIR...")
		os.Exit(2)
	}

	allow, err := loadAllow(*allowPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "namecheck:", err)
		os.Exit(2)
	}
	root, _ := os.Getwd()
	r := &reporter{fset: token.NewFileSet(), allow: allow, root: root}

	for _, dir := range flag.Args() {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// go/parser, not a regexp: this is what makes a /* */ block
			// invisible rather than something to be pattern-matched around.
			f, perr := parser.ParseFile(r.fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return fmt.Errorf("parsing %s: %w", path, perr)
			}
			r.checkKeyFold(f)
			r.checkNameCmp(f)
			r.checkFoldPair(f)
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "namecheck:", err)
			os.Exit(2)
		}
	}

	sort.Slice(r.findings, func(i, j int) bool {
		if r.findings[i].pos.Filename != r.findings[j].pos.Filename {
			return r.findings[i].pos.Filename < r.findings[j].pos.Filename
		}
		return r.findings[i].pos.Line < r.findings[j].pos.Line
	})
	for _, f := range r.findings {
		fmt.Printf("%s:%d:%d: [%s] %s\n", f.pos.Filename, f.pos.Line, f.pos.Column, f.check, f.msg)
	}
	if len(r.findings) > 0 {
		fmt.Fprintf(os.Stderr, "\nnamecheck: %d finding(s)\n", len(r.findings))
		os.Exit(1)
	}
}
