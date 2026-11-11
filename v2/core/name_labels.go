/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import "github.com/miekg/dns"

// TrimLeadingLabels returns name with its first n labels removed, spelled as
// name spells it, or "" when name has no more than n labels.
//
// For cutting off a prefix that was tested on the canonical name. Slicing the
// original by the prefix's length in bytes assumes the original spells the
// prefix in as many bytes as the canonical name does. Folding case keeps that
// true; an escape does not -- \_dns. is six bytes where _dns. is five -- and a
// cut by bytes lands inside the next label. A label is a label in every
// spelling, so counting labels cuts in the same place whatever the spelling.
func TrimLeadingLabels(name string, n int) string {
	off := 0
	for ; n > 0; n-- {
		next, end := dns.NextLabel(name, off)
		if end {
			return ""
		}
		off = next
	}
	return name[off:]
}
