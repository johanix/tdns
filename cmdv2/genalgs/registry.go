package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
)

// These mirror the fields the generator consumes from the registry's
// Alg / Caps types. The generator resolves the registry source into
// these by walking its AST — it does not import the registry package.

type Caps struct {
	ForSIG0   bool
	ForDNSSEC bool
	ForKSK    bool
	ForZSK    bool
}

type Alg struct {
	Codepoint uint8
	Name      string
	Caps      Caps
	Package   string
	Group     string
	Facts     Facts // joined from AlgorithmFacts by Name; zero if none
}

// Facts mirrors the registry's Facts struct — static, spec-fixed
// enrichment. Parsed from the AlgorithmFacts map and joined to each Alg
// by Name. All fields optional (zero = "not provided").
type Facts struct {
	PubKeyBytes   int
	SigBytes      int
	SecKeyBytes   int
	SecurityLevel int
	Maturity      string
	Description   string
}

const groupPureGo = "purego"

// parseRegistry reads dnssec-algorithms' registry/registry.go and
// extracts the `Algorithms` slice. It resolves the exact idioms that
// file uses: named Caps shorthands (dnssec, kskOnly), the `base` string
// const with `base + "..."` concatenation for Package, and the Group
// constants (whose STRING VALUE — "purego"/"liboqs"/... — is what we
// need, taken from their const declarations). Anything it does not
// recognize is a hard error, so a future style change in registry.go
// fails loudly here rather than silently dropping algorithms.
func parseRegistry(path string) ([]Alg, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}

	capsVars := map[string]Caps{} // dnssec, kskOnly -> Caps
	strConsts := map[string]string{}
	groupConsts := map[string]string{} // PureGo -> "purego", etc.
	var algsExpr *ast.CompositeLit
	var factsExpr *ast.CompositeLit

	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			name := vs.Names[0].Name
			switch gd.Tok {
			case token.CONST:
				// String constants: `base = "..."` and the Group
				// constants `PureGo Group = "purego"`.
				if s, ok := stringLit(vs.Values[0]); ok {
					strConsts[name] = s
					groupConsts[name] = s // harmless overlap; Group consts land here too
				}
			case token.VAR:
				switch name {
				case "Algorithms":
					cl, ok := vs.Values[0].(*ast.CompositeLit)
					if !ok {
						return nil, fmt.Errorf("Algorithms is not a composite literal")
					}
					algsExpr = cl
				case "AlgorithmFacts":
					cl, ok := vs.Values[0].(*ast.CompositeLit)
					if !ok {
						return nil, fmt.Errorf("AlgorithmFacts is not a composite literal")
					}
					factsExpr = cl
				default:
					// Caps shorthand vars: `dnssec = Caps{...}`.
					if c, ok := capsLit(vs.Values[0]); ok {
						capsVars[name] = c
					}
				}
			}
		}
	}
	if algsExpr == nil {
		return nil, fmt.Errorf("no `Algorithms` var found")
	}

	// Parse AlgorithmFacts (map[string]Facts keyed by name). Absent is
	// tolerated (older registry); each algorithm without an entry keeps
	// zero-value Facts.
	facts, err := parseFacts(factsExpr)
	if err != nil {
		return nil, err
	}

	var out []Alg
	for i, el := range algsExpr.Elts {
		row, ok := el.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("Algorithms[%d]: not a struct literal", i)
		}
		if len(row.Elts) != 5 {
			return nil, fmt.Errorf("Algorithms[%d]: expected 5 fields, got %d", i, len(row.Elts))
		}

		cp, err := intLit(row.Elts[0])
		if err != nil {
			return nil, fmt.Errorf("Algorithms[%d] codepoint: %w", i, err)
		}
		name, ok := stringLit(row.Elts[1])
		if !ok {
			return nil, fmt.Errorf("Algorithms[%d] name: not a string literal", i)
		}
		caps, err := resolveCaps(row.Elts[2], capsVars)
		if err != nil {
			return nil, fmt.Errorf("Algorithms[%d] (%s) caps: %w", i, name, err)
		}
		pkg, err := resolveString(row.Elts[3], strConsts)
		if err != nil {
			return nil, fmt.Errorf("Algorithms[%d] (%s) package: %w", i, name, err)
		}
		group, err := resolveGroup(row.Elts[4], groupConsts)
		if err != nil {
			return nil, fmt.Errorf("Algorithms[%d] (%s) group: %w", i, name, err)
		}
		out = append(out, Alg{
			Codepoint: uint8(cp),
			Name:      name,
			Caps:      caps,
			Package:   pkg,
			Group:     group,
			Facts:     facts[name], // zero value if no AlgorithmFacts entry
		})
	}
	return out, nil
}

// parseFacts resolves the AlgorithmFacts map literal (map[string]Facts,
// keyed by name) into a name->Facts map. A nil expr (no AlgorithmFacts in
// the registry) yields an empty map. Each value is a Facts struct literal
// with keyed fields; unknown field names are a hard error so a registry
// schema change fails loudly rather than silently dropping data.
func parseFacts(expr *ast.CompositeLit) (map[string]Facts, error) {
	out := map[string]Facts{}
	if expr == nil {
		return out, nil
	}
	for i, el := range expr.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			return nil, fmt.Errorf("AlgorithmFacts[%d]: not a key:value entry", i)
		}
		name, ok := stringLit(kv.Key)
		if !ok {
			return nil, fmt.Errorf("AlgorithmFacts[%d]: key is not a string literal", i)
		}
		lit, ok := kv.Value.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("AlgorithmFacts[%q]: value is not a Facts literal", name)
		}
		var fct Facts
		for _, fe := range lit.Elts {
			fkv, ok := fe.(*ast.KeyValueExpr)
			if !ok {
				return nil, fmt.Errorf("AlgorithmFacts[%q]: fields must be keyed (Field: value)", name)
			}
			field, ok := fkv.Key.(*ast.Ident)
			if !ok {
				return nil, fmt.Errorf("AlgorithmFacts[%q]: field key is not an identifier", name)
			}
			switch field.Name {
			case "PubKeyBytes", "SigBytes", "SecKeyBytes", "SecurityLevel":
				n, err := intLit(fkv.Value)
				if err != nil {
					return nil, fmt.Errorf("AlgorithmFacts[%q].%s: %w", name, field.Name, err)
				}
				switch field.Name {
				case "PubKeyBytes":
					fct.PubKeyBytes = n
				case "SigBytes":
					fct.SigBytes = n
				case "SecKeyBytes":
					fct.SecKeyBytes = n
				case "SecurityLevel":
					fct.SecurityLevel = n
				}
			case "Maturity", "Description":
				s, ok := stringLit(fkv.Value)
				if !ok {
					return nil, fmt.Errorf("AlgorithmFacts[%q].%s: not a string literal", name, field.Name)
				}
				if field.Name == "Maturity" {
					fct.Maturity = s
				} else {
					fct.Description = s
				}
			default:
				return nil, fmt.Errorf("AlgorithmFacts[%q]: unknown field %q", name, field.Name)
			}
		}
		out[name] = fct
	}
	return out, nil
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

func intLit(e ast.Expr) (int, error) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.INT {
		return 0, fmt.Errorf("not an integer literal")
	}
	return strconv.Atoi(bl.Value)
}

// capsLit resolves a `Caps{ForSIG0: true, ...}` composite literal.
func capsLit(e ast.Expr) (Caps, bool) {
	cl, ok := e.(*ast.CompositeLit)
	if !ok {
		return Caps{}, false
	}
	var c Caps
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			return Caps{}, false
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			return Caps{}, false
		}
		val := boolLit(kv.Value)
		switch key.Name {
		case "ForSIG0":
			c.ForSIG0 = val
		case "ForDNSSEC":
			c.ForDNSSEC = val
		case "ForKSK":
			c.ForKSK = val
		case "ForZSK":
			c.ForZSK = val
		}
	}
	return c, true
}

func boolLit(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "true"
}

// resolveCaps handles a row's caps field: either a named shorthand
// (dnssec/kskOnly) or an inline Caps{...} literal.
func resolveCaps(e ast.Expr, vars map[string]Caps) (Caps, error) {
	if id, ok := e.(*ast.Ident); ok {
		c, ok := vars[id.Name]
		if !ok {
			return Caps{}, fmt.Errorf("unknown caps shorthand %q", id.Name)
		}
		return c, nil
	}
	if c, ok := capsLit(e); ok {
		return c, nil
	}
	return Caps{}, fmt.Errorf("unrecognized caps expression")
}

// resolveString handles a row's package field: a string literal, a named
// string const, or `const + "literal"` / `const + const` concatenation.
func resolveString(e ast.Expr, consts map[string]string) (string, error) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if s, ok := stringLit(v); ok {
			return s, nil
		}
		return "", fmt.Errorf("non-string literal")
	case *ast.Ident:
		s, ok := consts[v.Name]
		if !ok {
			return "", fmt.Errorf("unknown string const %q", v.Name)
		}
		return s, nil
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", fmt.Errorf("unsupported operator %s", v.Op)
		}
		l, err := resolveString(v.X, consts)
		if err != nil {
			return "", err
		}
		r, err := resolveString(v.Y, consts)
		if err != nil {
			return "", err
		}
		return l + r, nil
	}
	return "", fmt.Errorf("unrecognized string expression")
}

// resolveGroup returns the STRING VALUE of a Group constant identifier
// (e.g. PureGo -> "purego").
func resolveGroup(e ast.Expr, groupConsts map[string]string) (string, error) {
	id, ok := e.(*ast.Ident)
	if !ok {
		return "", fmt.Errorf("group is not an identifier")
	}
	s, ok := groupConsts[id.Name]
	if !ok {
		return "", fmt.Errorf("unknown group constant %q", id.Name)
	}
	return s, nil
}
