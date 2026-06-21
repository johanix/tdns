package tdns

import "testing"

// Step 1: the global dnssec.completeness knob. Verifies parse/validate
// (good values, default, bad value rejected). The behavior it gates
// (relaxed ZSK alg roll / strict refusal) lands with step 2.
func TestResolveCompletenessMode(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", CompletenessStrict, false},           // default
		{"strict", CompletenessStrict, false},     // explicit
		{"STRICT", CompletenessStrict, false},     // case-insensitive
		{" relaxed ", CompletenessRelaxed, false}, // trimmed
		{"relaxed", CompletenessRelaxed, false},
		{"loose", "", true}, // unknown → hard error
		{"true", "", true},  // not a bool
	}
	for _, c := range cases {
		got, err := resolveCompletenessMode(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("resolveCompletenessMode(%q): expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveCompletenessMode(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("resolveCompletenessMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
