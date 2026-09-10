/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package externaldb

import (
	"os"
	"strings"
	"testing"
)

// The DDL in the operator guide is the published interface. It is rendered
// from the same source as the code, and this keeps it that way.
func TestGuideCarriesTheShippedDDL(t *testing.T) {
	data, err := os.ReadFile("../../guide/childsync-proxy.md")
	if err != nil {
		t.Fatalf("operator guide not found: %v", err)
	}
	const marker = "<!-- DDL rendered from v2/externaldb/schema.go; a test keeps it in sync -->\n```sql\n"
	i := strings.Index(string(data), marker)
	if i < 0 {
		t.Fatal("the guide has no marked DDL block")
	}
	rest := string(data)[i+len(marker):]
	j := strings.Index(rest, "```")
	if j < 0 {
		t.Fatal("the guide's DDL block is not closed")
	}
	if got, want := rest[:j], DDL(DefaultTablePrefix); got != want {
		t.Fatalf("the guide's DDL differs from DDL(%q); re-render it from schema.go", DefaultTablePrefix)
	}
}
