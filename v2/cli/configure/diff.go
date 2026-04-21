/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Bootstrap-configure library: diff preview + top-level confirmation.
 *
 * Substitution templates produce deterministic output where most
 * lines are stable and only a handful differ per re-run. That
 * makes a simple positional line-diff adequate.
 *
 * The confirmation gate here is a single top-level yes/no for
 * all files. Per-file confirmation belongs to the live-server
 * gate in ping.go.
 */
package configure

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// FileChange is one pending rewrite. If OldTxt is empty the file
// does not exist yet; the diff preview treats the whole NewTxt
// as added.
type FileChange struct {
	Path   string
	OldTxt string
	NewTxt string
}

// Changed reports whether content is going to move.
func (c FileChange) Changed() bool { return c.OldTxt != c.NewTxt }

// PreviewDiff writes a human-readable diff for c to w.
func PreviewDiff(w io.Writer, c FileChange) {
	if c.OldTxt == "" {
		fmt.Fprintf(w, "\n--- %s (new file, %d lines) ---\n", c.Path, lineCount(c.NewTxt))
		for _, line := range splitLines(c.NewTxt) {
			fmt.Fprintf(w, "+ %s\n", line)
		}
		return
	}

	oldLines := splitLines(c.OldTxt)
	newLines := splitLines(c.NewTxt)
	fmt.Fprintf(w, "\n--- %s ---\n", c.Path)

	n := len(oldLines)
	if len(newLines) > n {
		n = len(newLines)
	}
	for i := 0; i < n; i++ {
		var o, ne string
		if i < len(oldLines) {
			o = oldLines[i]
		}
		if i < len(newLines) {
			ne = newLines[i]
		}
		switch {
		case i >= len(oldLines):
			fmt.Fprintf(w, "+ %s\n", ne)
		case i >= len(newLines):
			fmt.Fprintf(w, "- %s\n", o)
		case o == ne:
			fmt.Fprintf(w, "  %s\n", o)
		default:
			fmt.Fprintf(w, "- %s\n", o)
			fmt.Fprintf(w, "+ %s\n", ne)
		}
	}
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

func lineCount(s string) int { return len(splitLines(s)) }

// confirmApply shows all pending changes and asks for a single
// top-level yes/no. Returns true iff the user typed "yes"
// (case-insensitive, exact).
func confirmApply(w io.Writer, in *bufio.Reader, changes []FileChange) bool {
	pending := make([]FileChange, 0, len(changes))
	for _, c := range changes {
		if c.Changed() {
			pending = append(pending, c)
		}
	}
	if len(pending) == 0 {
		fmt.Fprintln(w, "\nNo changes to apply.")
		return false
	}
	for _, c := range pending {
		PreviewDiff(w, c)
	}
	fmt.Fprintf(w, "\nApply %d file change(s)? Type 'yes' to confirm: ", len(pending))
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	// Deliberately case-sensitive. A typed-confirmation gate is
	// meant to force intentionality; "YES" is the kind of thing a
	// shell autocomplete or paste buffer can produce by accident,
	// so we require the exact lowercase literal.
	return strings.TrimSpace(line) == "yes"
}

// applyChanges writes each pending change using atomicWrite.
// Returns the list of backup paths created (for reporting).
//
// No rollback on partial failure. atomicWrite is atomic per file
// (rename(2)), but this function walks the slice sequentially —
// if the 3rd of 4 writes fails, the first two are already on
// disk. We deliberately do not try to undo them, because:
//
//   - The user has seen the full diff and confirmed the intent.
//   - Backups of every replaced file are still on disk (.bak.<ts>).
//   - Automatic rollback would have to handle the case where a
//     restore itself fails, giving worse failure modes than "stop
//     and let the operator look at the backups."
//
// Callers should report the returned error and point at the
// backup paths for recovery.
func applyChanges(w io.Writer, changes []FileChange) ([]string, error) {
	var backups []string
	for _, c := range changes {
		if !c.Changed() {
			continue
		}
		bak, err := atomicWrite(c.Path, c.NewTxt)
		if err != nil {
			return backups, err
		}
		if bak != "" {
			fmt.Fprintf(w, "  wrote %s (backup: %s)\n", c.Path, bak)
			backups = append(backups, bak)
		} else {
			fmt.Fprintf(w, "  wrote %s (new)\n", c.Path)
		}
	}
	return backups, nil
}
