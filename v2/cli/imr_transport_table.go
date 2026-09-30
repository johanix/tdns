/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"fmt"
	"sort"
	"strings"

	tdns "github.com/johanix/tdns/v2"
)

// What "imr stats auth-transports" and "imr stats client-transports" share:
// the transport columns, --pct, and the per-privacy-level rows of --privacy.

// privacyRowOrder is the order of the rows --privacy shows under a server or
// client. "internal" (the resolver's own lookups) occurs on the auth side only.
var privacyRowOrder = []string{"none", "opportunistic", "strict", "internal"}

// privacyLabel is a level's name in the PRIVACY column.
func privacyLabel(level string) string {
	if level == "opportunistic" {
		return "opp."
	}
	return level
}

// countRow is one row's counts: all of a server's or client's, or with
// --privacy those of one level.
type countRow struct {
	level  string // "" without --privacy
	counts map[string]uint64
	total  uint64
}

// countRows is the rows to show for one server or client: one with the totals,
// or with privacy one per level it used, in privacyRowOrder. A server or client
// with nothing counted per level (no answers, or a resolver that predates the
// split) gets one row, level "-".
func countRows(counts map[string]uint64, total uint64, byPrivacy map[string]map[string]uint64, privacy bool) []countRow {
	if !privacy {
		return []countRow{{counts: counts, total: total}}
	}
	var rows []countRow
	for _, level := range privacyRowOrder {
		c, ok := byPrivacy[level]
		if !ok {
			continue
		}
		var n uint64
		for _, v := range c {
			n += v
		}
		rows = append(rows, countRow{level: level, counts: c, total: n})
	}
	if len(rows) == 0 {
		return []countRow{{level: "-", counts: counts, total: total}}
	}
	return rows
}

// transportCells is a row's transport columns, counts or with pct shares of
// the row's total.
func transportCells(counts map[string]uint64, total uint64, pct bool) []string {
	cells := make([]string, 0, len(tdns.ImrClientTransports))
	for _, t := range tdns.ImrClientTransports {
		cells = append(cells, countOrShare(counts[t], total, pct))
	}
	return cells
}

// levelTotals adds rows up per level, for the TOTAL rows.
type levelTotals struct {
	order  []string
	counts map[string]map[string]uint64
	total  map[string]uint64
}

func newLevelTotals() *levelTotals {
	return &levelTotals{counts: map[string]map[string]uint64{}, total: map[string]uint64{}}
}

func (lt *levelTotals) add(r countRow) {
	if r.level == "-" && r.total == 0 {
		return // a row with nothing counted, split or not: no TOTAL row of its own
	}
	if _, ok := lt.counts[r.level]; !ok {
		lt.counts[r.level] = map[string]uint64{}
		lt.order = append(lt.order, r.level)
	}
	for t, n := range r.counts {
		lt.counts[r.level][t] += n
	}
	lt.total[r.level] += r.total
}

// rows is the TOTAL rows: one per level seen, in privacyRowOrder, or the one
// row without --privacy.
func (lt *levelTotals) rows() []countRow {
	rank := map[string]int{"": -1, "-": len(privacyRowOrder)}
	for i, l := range privacyRowOrder {
		rank[l] = i
	}
	order := append([]string(nil), lt.order...)
	sort.SliceStable(order, func(i, j int) bool { return rank[order[i]] < rank[order[j]] })
	if len(order) == 0 {
		order = []string{""}
	}
	out := make([]countRow, 0, len(order))
	for _, l := range order {
		out = append(out, countRow{level: l, counts: lt.counts[l], total: lt.total[l]})
	}
	return out
}

// countOrShare is n, or with pct n's share of total. A share that rounds to 0
// or 100 without being either says so, so that a few queries are not hidden.
func countOrShare(n, total uint64, pct bool) string {
	if !pct {
		return fmt.Sprint(n)
	}
	if total == 0 {
		return "-"
	}
	p := (n*100 + total/2) / total
	switch {
	case n > 0 && p == 0:
		return "<1%"
	case n < total && p == 100:
		return ">99%"
	}
	return fmt.Sprintf("%d%%", p)
}

// signalOrder is the order of the transports in the OOTS and EXPECTED columns:
// that of the table's transport columns.
var signalOrder = []string{"do53", "dot", "doq", "doh"}

// orderedTransports is the transports of m in signalOrder, then any others
// sorted.
func orderedTransports[V any](m map[string]V) []string {
	known := map[string]bool{}
	var out []string
	for _, t := range signalOrder {
		known[t] = true
		if _, ok := m[t]; ok {
			out = append(out, t)
		}
	}
	var rest []string
	for t := range m {
		if !known[t] {
			rest = append(rest, t)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// joinCells joins a row's cells for the tabwriter, padded with empty cells to
// n. Every row has every cell: tabwriter aligns a column only over an unbroken
// run of lines that have it, so a short row would split the table. The padding
// this leaves at the ends of lines goes in trimLineEnds.
func joinCells(cols []string, n int) string {
	for len(cols) < n {
		cols = append(cols, "")
	}
	return strings.Join(cols, "\t")
}

// trimLineEnds removes the spaces at the ends of the lines of s.
func trimLineEnds(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.Join(lines, "\n")
}
