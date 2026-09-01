package cli

import (
	"reflect"
	"strings"
	"testing"
)

// CliConf is a config root in its own right, decoded by the CLI roots through
// viper.Unmarshal — and it is not reachable from tdns.Config, so the guard test
// over there cannot see it. Same rule, same failure if it is broken: a yaml key
// that differs from its lowercased field name and carries no mapstructure tag
// decodes to the zero value in silence. ApiDetails.ConfigFile ("config-file")
// was exactly that.
//
// The walk is duplicated rather than exported from the tdns package: a test
// helper is not worth widening the public API for.
func TestCliConfYamlKeysAreMappable(t *testing.T) {
	var problems []string
	seen := map[reflect.Type]bool{}

	var walk func(reflect.Type, string)
	walk = func(t0 reflect.Type, path string) {
		for t0.Kind() == reflect.Ptr || t0.Kind() == reflect.Slice ||
			t0.Kind() == reflect.Array || t0.Kind() == reflect.Map {
			t0 = t0.Elem()
		}
		if t0.Kind() != reflect.Struct || seen[t0] {
			return
		}
		seen[t0] = true
		for i := 0; i < t0.NumField(); i++ {
			f := t0.Field(i)
			if f.PkgPath != "" {
				continue
			}
			where := path + "." + t0.Name() + "." + f.Name
			y, hasYaml := f.Tag.Lookup("yaml")
			if hasYaml {
				y = strings.Split(y, ",")[0]
			}
			ms, hasMS := f.Tag.Lookup("mapstructure")
			if hasMS {
				ms = strings.Split(ms, ",")[0]
			}
			switch {
			case !hasYaml || y == "" || y == "-":
			case hasMS && ms == "-":
			case strings.Contains(y, "_"):
				problems = append(problems, where+": yaml:\""+y+"\" uses underscores; config keys use hyphens")
			case !hasMS && !strings.EqualFold(y, f.Name):
				problems = append(problems, where+": yaml:\""+y+"\" differs from the field name and has no mapstructure tag — viper will silently ignore it")
			case hasMS && !strings.EqualFold(ms, y):
				problems = append(problems, where+": yaml:\""+y+"\" and mapstructure:\""+ms+"\" disagree")
			}
			walk(f.Type, path+"."+t0.Name())
		}
	}
	walk(reflect.TypeOf(CliConf{}), "")

	for _, p := range problems {
		t.Error(p)
	}
	if len(seen) == 0 {
		t.Error("walk reached no structs at all")
	}
}
