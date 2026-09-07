package tdns

import (
	"strings"
	"testing"
)

// The delegationsync: block's `parent:`/`child:` keys were named after the far
// end of the relationship they configure: `delegationsync.parent` is what a
// CHILDSYNC zone publishes. They are now `childsync:`/`parentsync:`, matching
// the zone options, with the old spellings accepted for a deprecation cycle.

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

// The deprecated key lands on the canonical field, and the shadow field is
// cleared so no reader downstream has to know both spellings.
func TestDeprecatedDelegationSyncKeysFold(t *testing.T) {
	var c Config
	m := map[string]interface{}{"delegationsync": map[string]interface{}{
		"parent": childsyncBlock(),
		"child":  parentsyncBlock(),
	}}
	if err := decodeConfigMap(m, &c, nil); err != nil {
		t.Fatalf("decode: %v", err)
	}
	ds := c.DelegationSync
	if got := ds.ChildSync.Update.Target; got != "updates.{ZONENAME}" {
		t.Errorf("childsync.update.target = %q, want it folded from the deprecated parent: block", got)
	}
	if got := len(ds.ChildSync.Schemes); got != 2 {
		t.Errorf("childsync.schemes = %d entries, want 2", got)
	}
	if got := len(ds.ParentSync.Schemes); got != 1 {
		t.Errorf("parentsync.schemes = %d entries, want 1", got)
	}
	if ds.DeprecatedParent != nil || ds.DeprecatedChild != nil {
		t.Error("the deprecated fields must be cleared after folding")
	}
}

// The canonical spelling decodes with nothing folded.
func TestCanonicalDelegationSyncKeys(t *testing.T) {
	var c Config
	m := map[string]interface{}{"delegationsync": map[string]interface{}{
		"childsync":  childsyncBlock(),
		"parentsync": parentsyncBlock(),
	}}
	if err := decodeConfigMap(m, &c, nil); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := c.DelegationSync.ChildSync.Update.Port; got != 53 {
		t.Errorf("childsync.update.port = %d, want 53", got)
	}
	if got := len(c.DelegationSync.ParentSync.Schemes); got != 1 {
		t.Errorf("parentsync.schemes = %d entries, want 1", got)
	}
}

// Both spellings for the same side is a half-finished migration. Refuse it
// rather than pick a winner: the operator would be reading one block while the
// server obeyed the other.
func TestBothSpellingsIsAnError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block map[string]interface{}
		want  string
	}{
		{"childsync and parent", map[string]interface{}{
			"childsync": childsyncBlock(), "parent": childsyncBlock(),
		}, "`parent:`"},
		{"parentsync and child", map[string]interface{}{
			"parentsync": parentsyncBlock(), "child": parentsyncBlock(),
		}, "`child:`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Config
			err := decodeConfigMap(map[string]interface{}{"delegationsync": tc.block}, &c, nil)
			if err == nil {
				t.Fatal("both spellings decoded without error")
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
func TestEmptyDeprecatedBlockDoesNotEraseCanonical(t *testing.T) {
	var c Config
	m := map[string]interface{}{"delegationsync": map[string]interface{}{
		"childsync": childsyncBlock(),
	}}
	if err := decodeConfigMap(m, &c, nil); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := c.DelegationSync.ChildSync.Update.Target; got != "updates.{ZONENAME}" {
		t.Fatalf("childsync.update.target = %q before folding again", got)
	}
	// Folding a second time is a no-op, so a reload cannot lose the block.
	if err := c.DelegationSync.FoldDeprecatedDelegationSyncKeys(); err != nil {
		t.Fatalf("second fold: %v", err)
	}
	if got := c.DelegationSync.ChildSync.Update.Target; got != "updates.{ZONENAME}" {
		t.Errorf("childsync.update.target = %q after a second fold, want it unchanged", got)
	}
}
