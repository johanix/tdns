package cli

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

// ------------------------------------------------------------------- cloning

// A copy that misses a field silently changes the command it copies: a dropped
// Args validator accepts bad input, a dropped Hidden shows a hidden command.
// So set EVERY exported field of cobra.Command to a marker value, copy, and
// require the copy to carry each one. A cobra upgrade that adds a field this
// does not know how to fill fails here, telling you to teach cloneCmd.
func TestCloneCopiesEveryCobraField(t *testing.T) {
	src := &cobra.Command{}
	sv := reflect.ValueOf(src).Elem()
	st := sv.Type()

	for i := 0; i < st.NumField(); i++ {
		f, fv := st.Field(i), sv.Field(i)
		if !f.IsExported() {
			continue
		}
		switch fv.Kind() {
		case reflect.String:
			fv.SetString("marker-" + f.Name)
		case reflect.Bool:
			fv.SetBool(true)
		case reflect.Int:
			fv.SetInt(7)
		case reflect.Slice:
			if fv.Type().Elem().Kind() != reflect.String {
				t.Fatalf("cobra.Command.%s is a %s: teach this test and cloneCmd about it", f.Name, f.Type)
			}
			fv.Set(reflect.ValueOf([]string{"marker-" + f.Name}).Convert(fv.Type()))
		case reflect.Map:
			fv.Set(reflect.ValueOf(map[string]string{"k": "v-" + f.Name}))
		case reflect.Func:
			fv.Set(reflect.MakeFunc(fv.Type(), func(args []reflect.Value) []reflect.Value {
				out := make([]reflect.Value, fv.Type().NumOut())
				for j := range out {
					out[j] = reflect.Zero(fv.Type().Out(j))
				}
				return out
			}))
		case reflect.Struct:
			// FParseErrWhitelist, CompletionOptions: bool fields only.
			for j := 0; j < fv.NumField(); j++ {
				if fv.Field(j).Kind() != reflect.Bool {
					t.Fatalf("cobra.Command.%s has a %s field: teach this test and cloneCmd about it", f.Name, fv.Field(j).Kind())
				}
				fv.Field(j).SetBool(true)
			}
		default:
			t.Fatalf("cobra.Command.%s is a %s: teach this test and cloneCmd about it", f.Name, f.Type)
		}
	}

	dst := cloneCmd(src, nil)
	dv := reflect.ValueOf(dst).Elem()

	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if !f.IsExported() {
			continue
		}
		a, b := sv.Field(i), dv.Field(i)
		if f.Name == "Annotations" {
			// Copied, but never the role annotation: the copy is about to sit
			// in another tree. (Not set here, so this just checks the rest.)
			if !reflect.DeepEqual(a.Interface(), b.Interface()) {
				t.Errorf("Annotations not copied: %v vs %v", a.Interface(), b.Interface())
			}
			continue
		}
		if a.Kind() == reflect.Func {
			if a.Pointer() != b.Pointer() {
				t.Errorf("func field %s was not copied", f.Name)
			}
			continue
		}
		if !reflect.DeepEqual(a.Interface(), b.Interface()) {
			t.Errorf("field %s was not copied: %v vs %v", f.Name, a.Interface(), b.Interface())
		}
	}
}

func TestCloneIsIndependentOfItsSource(t *testing.T) {
	var verbose bool
	child := &cobra.Command{Use: "child", Short: "c", Run: func(*cobra.Command, []string) {}}
	other := &cobra.Command{Use: "other"}
	src := TagRole(&cobra.Command{Use: "src", Short: "s"}, "imr")
	src.Annotations["keep"] = "me"
	src.Flags().BoolVar(&verbose, "verbose-thing", false, "a local flag")
	src.PersistentFlags().String("pers", "", "a persistent flag")
	src.AddCommand(child, other)

	all := cloneCmdTree(src)
	if all.Parent() != nil || len(all.Commands()) != 2 {
		t.Fatalf("clone: parent %v, %d children", all.Parent(), len(all.Commands()))
	}
	if all.Commands()[0] == child || all.Commands()[1] == other {
		t.Error("children were shared, not copied")
	}
	if all.Annotations[roleAnnotation] != "" || all.Annotations["keep"] != "me" {
		t.Errorf("annotations: %v (role must not be copied, the rest must)", all.Annotations)
	}
	if all.Flags().Lookup("verbose-thing") == nil || all.PersistentFlags().Lookup("pers") == nil {
		t.Error("flags were not copied")
	}
	// Re-parenting the copy must not touch the original.
	root := &cobra.Command{Use: "root"}
	root.AddCommand(all)
	if src.Parent() != nil || child.Parent() != src {
		t.Error("attaching the copy changed the original's parentage")
	}

	only := cloneCmdOnly(src, func(n string) bool { return n == "child" })
	if len(only.Commands()) != 1 || only.Commands()[0].Name() != "child" {
		t.Errorf("cloneCmdOnly kept %d children", len(only.Commands()))
	}
}

// ------------------------------------------------------------------ the tree

func TestNewImrTreeIsIndependentPerRole(t *testing.T) {
	a := NewImrTree("imr", "imr")
	b := NewImrTree("imr2", "imr2")
	if a == b || a.Name() != "imr" || b.Name() != "imr2" {
		t.Fatal("trees are not independent")
	}
	if len(a.Commands()) == 0 || len(a.Commands()) != len(b.Commands()) {
		t.Fatalf("trees differ in size: %d vs %d", len(a.Commands()), len(b.Commands()))
	}
	for _, path := range []string{"flush all", "flush common", "query", "stats transport-stats suffix", "stats auth-transports", "config check", "forward list", "stub status", "ping"} {
		if got := RoleForCmd(mustFindCmd(t, b, path)); got != "imr2" {
			t.Errorf("imr2 %s targets %q", path, got)
		}
	}
	// What is deliberately left off.
	for _, path := range []string{"show", "set", "zone", "dsync-query", "stats large-ksk"} {
		if c := findPath(b, path); c != nil {
			t.Errorf("imr instance offers %q, which has no API target", path)
		}
	}
	// stats is a plain parent: its in-process Run is not carried over.
	if stats := mustFindCmd(t, b, "stats"); stats.Run != nil || stats.RunE != nil {
		t.Error("an imr instance's bare `stats` would report the CLI process's own metrics")
	}
}

func findPath(root *cobra.Command, path string) *cobra.Command {
	c := root
	for _, w := range strings.Fields(path) {
		if c = findChild(c, w); c == nil {
			return nil
		}
	}
	return c
}

func TestImrInstanceIsWired(t *testing.T) {
	withCleanRoleRegistry(t)
	root := &cobra.Command{Use: "tdns-ncli"}
	w := WireInstanceTrees(root, []ApiDetails{
		{Name: "tdns-imr", BaseURL: "http://127.0.0.1:8080/api/v1"},
		{Name: "imr2", Role: "imr", BaseURL: "http://127.0.0.1:8081/api/v1"},
	})
	if len(w) != 0 || findChild(root, "imr2") == nil {
		t.Fatalf("warnings %v, imr2 wired: %v", w, findChild(root, "imr2") != nil)
	}
}

// The point of all of it. Every imr command that talks to a daemon used to say
// "imr" outright, so `imr2 flush all x.` would have flushed the FIRST
// resolver's cache and reported success. Run each API-backed command through a
// second instance, against two live servers, and require that the second
// instance's server saw it and the canonical one saw nothing; then the
// reverse, through the canonical tree.
func TestImrInstanceCommandsReachTheirOwnDaemon(t *testing.T) {
	withCleanRoleRegistry(t)
	RegisterRole("imr2", "imr2")

	type seen struct {
		mu   sync.Mutex
		hits []string
	}
	record := func(s *seen, what string) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.hits = append(s.hits, what)
	}
	serve := func(s *seen) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/imr":
				var post tdns.ImrMgmtPost
				_ = json.NewDecoder(r.Body).Decode(&post)
				record(s, post.Command)
				resp := tdns.ImrMgmtResponse{Msg: "ok"}
				if post.Command == "imr-transport-stats" {
					resp.Data = []interface{}{}
				} else {
					resp.Data = map[string]interface{}{}
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "/api/v1/config":
				record(s, "config-status")
				_ = json.NewEncoder(w).Encode(tdns.ConfigResponse{Msg: "ok"})
			default:
				http.NotFound(w, r)
			}
		}))
	}
	var canon, inst seen
	sCanon, sInst := serve(&canon), serve(&inst)
	defer sCanon.Close()
	defer sInst.Close()

	savedClients, savedType := tdns.Globals.ApiClients, tdns.Globals.App.Type
	tdns.Globals.ApiClients = map[string]*tdns.ApiClient{
		"tdns-imr": tdns.NewClient("tdns-imr", sCanon.URL+"/api/v1", "k1", "X-API-Key", "insecure"),
		"imr2":     tdns.NewClient("imr2", sInst.URL+"/api/v1", "k2", "X-API-Key", "insecure"),
	}
	tdns.Globals.App.Type = tdns.AppTypeCli // so the commands take their API path
	t.Cleanup(func() { tdns.Globals.ApiClients, tdns.Globals.App.Type = savedClients, savedType })

	run := func(tree *cobra.Command, path string, args ...string) {
		t.Helper()
		c := mustFindCmd(t, tree, path)
		c.SetContext(context.Background())
		c.Run(c, args)
	}

	canonTree := NewImrTree("imr", "imr")
	instTree := NewImrTree("imr2", "imr2")

	cases := []struct {
		path string
		args []string
		want string // what the daemon records
	}{
		{"flush all", []string{"example.com."}, "imr-flush"},
		{"flush common", []string{"example.com."}, "imr-flush"},
		{"query", []string{"example.com.", "A"}, "imr-resolve"},
		{"stats transport-stats", nil, "imr-transport-stats"},
		{"stats auth-transports", nil, "imr-auth-transports"},
		{"stats client-transports", nil, "imr-client-stats"},
	}
	for _, tc := range cases {
		canon.hits, inst.hits = nil, nil
		run(instTree, tc.path, tc.args...)
		if len(inst.hits) != 1 || inst.hits[0] != tc.want || len(canon.hits) != 0 {
			t.Errorf("imr2 %s: instance server saw %v, canonical server saw %v (want exactly %q on the instance)",
				tc.path, inst.hits, canon.hits, tc.want)
		}

		canon.hits, inst.hits = nil, nil
		run(canonTree, tc.path, tc.args...)
		if len(canon.hits) != 1 || canon.hits[0] != tc.want || len(inst.hits) != 0 {
			t.Errorf("imr %s: canonical server saw %v, instance server saw %v", tc.path, canon.hits, inst.hits)
		}
	}

	// config status goes to the right daemon too.
	canon.hits, inst.hits = nil, nil
	if _, err := fetchImrStatus("imr2"); err != nil || len(inst.hits) != 1 || len(canon.hits) != 0 {
		t.Errorf("fetchImrStatus(imr2): err %v, instance %v, canonical %v", err, inst.hits, canon.hits)
	}
}

// `imr2 config check` reads imr2's own config file by default, not the
// canonical /etc/tdns/tdns-imr.yaml.
func TestImrInstanceConfigCheckUsesItsOwnConfigFile(t *testing.T) {
	saved := apiConfig
	t.Cleanup(func() { apiConfig = saved })
	withCleanRoleRegistry(t)
	RegisterRole("imr2", "imr2")
	apiConfig = &CliConf{ApiServers: []ApiDetails{
		{Name: "tdns-imr", BaseURL: "http://127.0.0.1:8080/api/v1"},
		{Name: "imr2", Role: "imr", BaseURL: "http://127.0.0.1:8081/api/v1", ConfigFile: "/etc/tdns/tdns-imr2.yaml"},
	}}
	if got := defaultCfgFileForRole("imr2"); got != "/etc/tdns/tdns-imr2.yaml" {
		t.Errorf("imr2 config file = %q", got)
	}
	if got := defaultCfgFileForRole("imr"); got != tdns.DefaultImrCfgFile {
		t.Errorf("imr config file = %q, want the default %q", got, tdns.DefaultImrCfgFile)
	}
}

// ---------------------------------------------------------------- source guards

// The imr commands' API calls must never carry the literal role "imr" again:
// it compiles, passes every test of the command, and is wrong only once a
// second resolver exists. Parsed rather than grepped, for the reason the auth
// guard gives.
func TestNoHardcodedImrRoleInApiCalls(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// function -> index of its role argument
	roleArg := map[string]int{"SendImrMgmtCmd": 1, "SendImrFlush": 1, "GetApiClient": 0, "fetchImrStatus": 0}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			i, watched := roleArg[id.Name]
			if !watched || i >= len(call.Args) {
				return true
			}
			if lit, ok := call.Args[i].(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value == `"imr"` {
				t.Errorf(`%s:%d: %s hardcodes the "imr" role; use imrRoleFor(cmd) (or the role the factory was given), so a second imr instance is not silently driven as the first`,
					f, fset.Position(call.Pos()).Line, id.Name)
			}
			return true
		})
	}
}

// mustFindCmd walks a command path ("flush all") below root, failing the test
// if any word is missing.
func mustFindCmd(t *testing.T, root *cobra.Command, path string) *cobra.Command {
	t.Helper()
	c := findPath(root, path)
	if c == nil {
		t.Fatalf("no %q below %s", path, root.Name())
	}
	return c
}
