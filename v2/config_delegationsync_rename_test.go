package tdns

import (
	"strings"
	"testing"
)

// The `delegationsync:` block wrapped `parent:`, `child:` and `policies:` under
// a level that said nothing its members did not — and the two blocks were each
// named after the FAR END of the relationship they configure:
// `delegationsync.parent` is what a CHILDSYNC zone publishes. They are now
// top-level `childsync:` and `parentsync:`, with the policies at
// `childsync.policies:`, and the whole old block accepted for a deprecation
// cycle.

func childsyncBlock() map[string]interface{} {
	return map[string]interface{}{
		"schemes": []interface{}{"notify", "update"},
		"update": map[string]interface{}{
			"target": "updates.{ZONENAME}",
			"port":   53,
		},
	}
}

func parentsyncBlock() map[string]interface{} {
	return map[string]interface{}{
		"schemes": []interface{}{"update"},
	}
}

func policiesBlock() map[string]interface{} {
	return map[string]interface{}{
		"default": map[string]interface{}{
			"bootstrap": map[string]interface{}{"mechanisms": []interface{}{"at-ns"}},
		},
	}
}

// Pointer, not a value: Config carries a sync.Once, so copying it is a vet error.
func decodeInto(t *testing.T, m map[string]interface{}) *Config {
	t.Helper()
	c := &Config{}
	if err := decodeConfigMap(m, c, nil); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return c
}

// The whole retired block lands on the top-level fields, policies included, and
// the shadow field is cleared so no reader downstream knows both shapes.
func TestDeprecatedDelegationSyncBlockFolds(t *testing.T) {
	c := decodeInto(t, map[string]interface{}{"delegationsync": map[string]interface{}{
		"parent":   childsyncBlock(),
		"child":    parentsyncBlock(),
		"policies": policiesBlock(),
	}})
	if got := c.ChildSync.Update.Target; got != "updates.{ZONENAME}" {
		t.Errorf("childsync.update.target = %q, want it folded from delegationsync.parent:", got)
	}
	if got := len(c.ChildSync.Schemes); got != 2 {
		t.Errorf("childsync.schemes = %d entries, want 2", got)
	}
	if got := len(c.ParentSync.Schemes); got != 1 {
		t.Errorf("parentsync.schemes = %d entries, want 1", got)
	}
	if _, ok := c.ChildSync.Policies["default"]; !ok {
		t.Errorf("childsync.policies = %v, want the default policy folded in", c.ChildSync.Policies)
	}
	if c.DeprecatedDelegationSync != nil {
		t.Error("the deprecated block must be cleared after folding")
	}
}

// The canonical shape decodes with nothing folded.
func TestCanonicalTopLevelBlocks(t *testing.T) {
	cs := childsyncBlock()
	cs["policies"] = policiesBlock()
	c := decodeInto(t, map[string]interface{}{
		"childsync":  cs,
		"parentsync": parentsyncBlock(),
	})
	if got := c.ChildSync.Update.Port; got != 53 {
		t.Errorf("childsync.update.port = %d, want 53", got)
	}
	if got := len(c.ParentSync.Schemes); got != 1 {
		t.Errorf("parentsync.schemes = %d entries, want 1", got)
	}
	if _, ok := c.ChildSync.Policies["default"]; !ok {
		t.Errorf("childsync.policies = %v, want the default policy", c.ChildSync.Policies)
	}
}

// Moving the blocks but not yet the policies is a coherent half-step, not a
// contradiction: it folds, with a warning, rather than failing.
func TestDeprecatedPoliciesFoldOntoTopLevelChildsync(t *testing.T) {
	c := decodeInto(t, map[string]interface{}{
		"childsync":      childsyncBlock(),
		"parentsync":     parentsyncBlock(),
		"delegationsync": map[string]interface{}{"policies": policiesBlock()},
	})
	if _, ok := c.ChildSync.Policies["default"]; !ok {
		t.Errorf("childsync.policies = %v, want the deprecated policies folded in", c.ChildSync.Policies)
	}
	if got := c.ChildSync.Update.Target; got != "updates.{ZONENAME}" {
		t.Errorf("childsync.update.target = %q, want the top-level block preserved", got)
	}
}

// Setting a member in both places is a half-finished migration. Refuse it
// rather than pick a winner: the operator would be reading one block while the
// server obeyed the other.
func TestBothShapesIsAnError(t *testing.T) {
	csWithPolicies := childsyncBlock()
	csWithPolicies["policies"] = policiesBlock()

	for _, tc := range []struct {
		name string
		m    map[string]interface{}
		want string
	}{
		{"childsync and delegationsync.parent", map[string]interface{}{
			"childsync":      childsyncBlock(),
			"delegationsync": map[string]interface{}{"parent": childsyncBlock()},
		}, "delegationsync.parent:"},
		{"parentsync and delegationsync.child", map[string]interface{}{
			"parentsync":     parentsyncBlock(),
			"delegationsync": map[string]interface{}{"child": parentsyncBlock()},
		}, "delegationsync.child:"},
		{"policies in both places", map[string]interface{}{
			"childsync":      csWithPolicies,
			"delegationsync": map[string]interface{}{"policies": policiesBlock()},
		}, "delegationsync.policies:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Config
			err := decodeConfigMap(tc.m, &c, nil)
			if err == nil {
				t.Fatal("both shapes decoded without error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not name the deprecated key: %v", err)
			}
		})
	}
}

// An EMPTY deprecated block must not erase a populated canonical one. This is
// why the shadow fields are pointers: with plain structs, "absent" and "present
// but empty" decode identically and the fold would silently blank the config.
//
// Two shapes, because they fail differently with plain structs:
//   - a bare `delegationsync:` with no members must fold to nothing at all;
//   - an empty MEMBER (`delegationsync: {parent: {}}`) beside a populated
//     childsync: is a half-finished migration and must be REFUSED. With plain
//     structs it is indistinguishable from absent, and the fold would blank a
//     populated block instead — silently, which is the whole failure mode.
func TestEmptyDeprecatedBlockDoesNotEraseCanonical(t *testing.T) {
	t.Run("bare wrapper", func(t *testing.T) {
		c := decodeInto(t, map[string]interface{}{
			"childsync":      childsyncBlock(),
			"delegationsync": map[string]interface{}{},
		})
		if got := c.ChildSync.Update.Target; got != "updates.{ZONENAME}" {
			t.Errorf("childsync.update.target = %q, want the canonical block untouched", got)
		}
		if got := len(c.ChildSync.Schemes); got != 2 {
			t.Errorf("childsync.schemes = %d entries, want 2", got)
		}
		if c.DeprecatedDelegationSync != nil {
			t.Error("the deprecated block must be cleared after folding")
		}
	})

	t.Run("empty member is refused", func(t *testing.T) {
		var c Config
		err := decodeConfigMap(map[string]interface{}{
			"childsync":      childsyncBlock(),
			"delegationsync": map[string]interface{}{"parent": map[string]interface{}{}},
		}, &c, nil)
		if err == nil {
			t.Fatalf("an empty deprecated `parent:` beside a populated childsync: was accepted;"+
				" childsync.update.target = %q", c.ChildSync.Update.Target)
		}
		if !strings.Contains(err.Error(), "delegationsync.parent:") {
			t.Errorf("error does not name the deprecated key: %v", err)
		}
	})

	t.Run("second fold is a no-op", func(t *testing.T) {
		c := decodeInto(t, map[string]interface{}{"childsync": childsyncBlock()})
		if err := c.FoldDeprecatedDelegationSync(); err != nil {
			t.Fatalf("second fold: %v", err)
		}
		if got := c.ChildSync.Update.Target; got != "updates.{ZONENAME}" {
			t.Errorf("childsync.update.target = %q after a second fold, want it unchanged", got)
		}
	})
}
