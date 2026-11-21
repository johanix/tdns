/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * What the parentsync commands print. The rules: lowercase, the verdict first,
 * nothing the operator does not need (the parent's UPDATE receiver in a sync
 * result, Go function names, an empty table column, the same error twice), and
 * no line longer than outputWidth, since a longer one wraps in a terminal.
 * Protocol names keep their case: UPDATE, NOTIFY, DSYNC, KEY, NOERROR, EDE.
 */
package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// outputWidth is the longest line the parentsync commands print.
const outputWidth = 72

// wrapLines word-wraps text to outputWidth: the first line starts with first,
// the rest with cont. A word longer than the room left gets a line of its own.
func wrapLines(text, first, cont string) []string {
	var out []string
	line := first
	empty := true
	for _, w := range strings.Fields(text) {
		if !empty && len(line)+1+len(w) > outputWidth {
			out = append(out, line)
			line, empty = cont, true
		}
		if !empty {
			line += " "
		}
		line += w
		empty = false
	}
	return append(out, line)
}

// writeLines prints each line.
func writeLines(w io.Writer, lines []string) {
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

// evenChunks splits s into the fewest pieces of at most max bytes, all of
// about the same length.
func evenChunks(s string, max int) []string {
	if max < 1 || len(s) <= max {
		return []string{s}
	}
	n := (len(s) + max - 1) / max
	size := (len(s) + n - 1) / n
	var out []string
	for len(s) > size {
		out = append(out, s[:size])
		s = s[size:]
	}
	return append(out, s)
}

// alignedLastField is line, whose last field is long (a key, a digest), broken
// so that no line exceeds outputWidth: the field continues on the next lines,
// aligned under its start. For reading, not for pasting into a zone file.
func alignedLastField(head, last string) []string {
	col := len(head)
	if col+len(last) <= outputWidth {
		return []string{head + last}
	}
	if outputWidth-col < 16 { // too little room after head: indent instead
		col = 8
	}
	chunks := evenChunks(last, outputWidth-col)
	out := []string{head + chunks[0]}
	for _, c := range chunks[1:] {
		out = append(out, strings.Repeat(" ", col)+c)
	}
	return out
}

// zoneFileLines is a record in presentation form laid out for a zone file:
// fields single-spaced and, when that is longer than outputWidth, the last
// field (the key) inside parentheses on lines of its own. Still a valid zone
// file entry, so it can be pasted as printed.
func zoneFileLines(rr string) []string {
	f := strings.Fields(rr)
	if len(f) == 0 {
		return nil
	}
	line := strings.Join(f, " ")
	if len(line) <= outputWidth || len(f) < 2 {
		return []string{line}
	}
	const indent = "        "
	chunks := evenChunks(f[len(f)-1], outputWidth-len(indent)-2)
	out := []string{strings.Join(f[:len(f)-1], " ") + " ("}
	for i, c := range chunks {
		if i == len(chunks)-1 {
			c += " )"
		}
		out = append(out, indent+c)
	}
	return out
}

// delegationChangeLines are the changes the parent needs, one per record:
// "+ NS    ns1.example." for one to add, "-" for one to remove. The owner is
// left out when it is the zone (NS, DS), kept for glue; TTLs are left out.
func delegationChangeLines(dss tdns.DelegationSyncStatus, indent string) []string {
	var out []string
	add := func(sign string, rrs []string) {
		for _, s := range rrs {
			out = append(out, changeLine(indent, sign, dss.ZoneName, s)...)
		}
	}
	add("+", dss.NsAddsStr)
	add("-", dss.NsRemovesStr)
	add("+", dss.AAddsStr)
	add("-", dss.ARemovesStr)
	add("+", dss.AAAAAddsStr)
	add("-", dss.AAAARemovesStr)
	add("+", dss.DSAddsStr)
	add("-", dss.DSRemovesStr)
	return out
}

func changeLine(indent, sign, zone, text string) []string {
	rr, err := dns.NewRR(text)
	if err != nil || rr == nil {
		return wrapLines(text, indent+sign+" ", indent+"  ")
	}
	f := strings.Fields(rr.String())
	if len(f) < 5 { // owner ttl class type rdata...
		return wrapLines(text, indent+sign+" ", indent+"  ")
	}
	rdata := f[4:]
	if !core.EqualNames(dns.Fqdn(rr.Header().Name), dns.Fqdn(zone)) {
		rdata = append([]string{rr.Header().Name}, rdata...)
	}
	head := fmt.Sprintf("%s%s %-6s", indent, sign, dns.TypeToString[rr.Header().Rrtype])
	if len(rdata) > 1 {
		head += strings.Join(rdata[:len(rdata)-1], " ") + " "
	}
	return alignedLastField(head, rdata[len(rdata)-1])
}

// unreadLine says what the comparison got no answer to, if anything: a
// verdict of "not in sync" with no changes listed is otherwise a puzzle.
func unreadLines(dss tdns.DelegationSyncStatus, indent string) []string {
	if len(dss.Unread) == 0 {
		return nil
	}
	return wrapLines("no answer for: "+strings.Join(dss.Unread, ", "), indent, indent+"  ")
}

// printDelegationDelta is "parentsync delta" (and "ddns del status"): "in
// sync", or "not in sync:" and the changes the parent needs.
func printDelegationDelta(w io.Writer, dss tdns.DelegationSyncStatus) {
	if dss.InSync {
		fmt.Fprintln(w, "in sync")
		return
	}
	fmt.Fprintln(w, "not in sync:")
	writeLines(w, delegationChangeLines(dss, "  "))
	writeLines(w, unreadLines(dss, "  "))
}

// parentAnswer describes the parent's answer to an UPDATE: whether there was
// one, the verdict ("accepted by parent (NOERROR)", "refused by parent (EDE
// 541)", "failed at parent (SERVFAIL)"), and the EDE text, if any.
func parentAnswer(ur tdns.UpdateResult) (answered bool, verdict, text string) {
	for _, ts := range ur.TargetStatus {
		if !ts.Error {
			answered = true
		}
	}
	if !answered && !ur.EDEFound {
		return false, "", ""
	}
	rcode := dns.RcodeToString[ur.Rcode]
	switch {
	case ur.Rcode == dns.RcodeSuccess:
		verdict = fmt.Sprintf("accepted by parent (%s)", rcode)
	case ur.Rcode == dns.RcodeRefused && ur.EDEFound:
		verdict = fmt.Sprintf("refused by parent (EDE %d)", ur.EDECode)
	case ur.Rcode == dns.RcodeRefused:
		verdict = "refused by parent (REFUSED)"
	case ur.EDEFound:
		verdict = fmt.Sprintf("failed at parent (%s, EDE %d)", rcode, ur.EDECode)
	default:
		verdict = fmt.Sprintf("failed at parent (%s)", rcode)
	}
	return true, verdict, ur.EDEMessage
}

// keySubject is how a key outcome starts: "key 38310", or what was attempted
// when there is no key to name.
func keySubject(keyid uint16, what string) string {
	if keyid == 0 {
		return what
	}
	return fmt.Sprintf("key %d", keyid)
}

// printBootstrapResult is "parentsync bootstrap": "key 38310: accepted by
// parent (NOERROR)", or the refusal with the parent's text. It reports
// whether the bootstrap succeeded.
func printBootstrapResult(w io.Writer, keyid uint16, ur tdns.UpdateResult, failed bool, errMsg string) bool {
	subject := keySubject(keyid, "bootstrap")
	answered, verdict, text := parentAnswer(ur)
	switch {
	case !failed && answered:
		fmt.Fprintf(w, "%s: %s\n", subject, verdict)
		return true
	case !failed:
		fmt.Fprintf(w, "%s: sent to parent\n", subject)
		return true
	case answered && ur.Rcode == dns.RcodeSuccess:
		// The parent took it; what failed came after, here.
		fmt.Fprintf(w, "%s: %s, then failed:\n", subject, verdict)
		writeLines(w, wrapLines(errMsg, "  ", "  "))
	case answered:
		fmt.Fprintf(w, "%s: %s\n", subject, verdict)
		if text != "" {
			writeLines(w, wrapLines(text, "  ", "  "))
		}
	default:
		fmt.Fprintf(w, "%s: bootstrap failed:\n", subject)
		writeLines(w, wrapLines(errMsg, "  ", "  "))
	}
	return false
}

// printRollResult is "parentsync roll-key": "key 16282: rolled to 40112
// (parent: NOERROR)", or the refusal. msg is the daemon's own line, printed
// for the hidden debug phases, which do not roll from one key to another.
func printRollResult(w io.Writer, oldID, newID uint16, ur tdns.UpdateResult, failed bool, errMsg, msg string) bool {
	answered, verdict, text := parentAnswer(ur)
	if !failed {
		if oldID == 0 || newID == 0 {
			writeLines(w, wrapLines(msg, "", "  "))
			return true
		}
		rcode := "NOERROR"
		if answered {
			rcode = dns.RcodeToString[ur.Rcode]
		}
		fmt.Fprintf(w, "key %d: rolled to %d (parent: %s)\n", oldID, newID, rcode)
		return true
	}
	subject := keySubject(oldID, "roll")
	switch {
	case answered && ur.Rcode != dns.RcodeSuccess:
		fmt.Fprintf(w, "%s: roll %s\n", subject, verdict)
		if text != "" {
			writeLines(w, wrapLines(text, "  ", "  "))
		}
	default:
		fmt.Fprintf(w, "%s: roll failed:\n", subject)
		writeLines(w, wrapLines(errMsg, "  ", "  "))
	}
	return false
}

// printInquireResult is "parentsync inquire": "key 38310: trusted
// (authenticated)".
func printInquireResult(w io.Writer, keyid uint16, state string, authenticated bool) {
	auth := "authenticated"
	if !authenticated {
		auth = "not authenticated"
	}
	fmt.Fprintf(w, "key %d: %s (%s)\n", keyid, strings.ToLower(state), auth)
}

// printSyncResult is "parentsync sync": what was sent and the parent's answer,
// or why nothing was. It reports whether the delegation is now in hand: in
// sync, or the change accepted.
func printSyncResult(w io.Writer, dss tdns.DelegationSyncStatus) bool {
	scheme := strings.ToLower(dss.Scheme)
	switch {
	case dss.InSync:
		fmt.Fprintln(w, "in sync; nothing sent")
		return true

	case dss.NothingSent:
		fmt.Fprintln(w, "not in sync; nothing sent:")
		for _, l := range strings.Split(dss.Msg, "\n") {
			writeLines(w, wrapLines(l, "  ", "    "))
		}
		return false

	case dss.Error:
		if scheme == "" {
			scheme = "sync"
		}
		answered, verdict, text := parentAnswer(dss.UpdateResult)
		if answered && dss.UpdateResult.Rcode != dns.RcodeSuccess {
			fmt.Fprintf(w, "%s %s:\n", scheme, verdict)
			if text != "" {
				writeLines(w, wrapLines(text, "  ", "  "))
			}
			return false
		}
		fmt.Fprintf(w, "%s failed:\n", scheme)
		writeLines(w, wrapLines(dss.ErrorMsg, "  ", "  "))
		return false
	}

	// Sent. A NOTIFY is handed to the notifier, so there is no parent rcode
	// to show for it.
	switch scheme {
	case "notify":
		fmt.Fprintln(w, "notify sent to parent:")
	case "":
		fmt.Fprintf(w, "sent to parent (%s):\n", dns.RcodeToString[int(dss.Rcode)])
	default:
		fmt.Fprintf(w, "%s sent to parent (%s):\n", scheme, dns.RcodeToString[int(dss.Rcode)])
	}
	writeLines(w, delegationChangeLines(dss, "  "))
	return true
}

// statusLabelWidth is the width of the label column in "parentsync status".
const statusLabelWidth = 12

// statusRow is one "label  value" line of the status report, the value
// wrapped under itself.
func statusRow(label, value string) []string {
	first := fmt.Sprintf("  %-*s", statusLabelWidth, label)
	return wrapLines(value, first, strings.Repeat(" ", len(first)))
}

// printParentSyncReport is "parentsync status" (#790): one line per question
// under the zone, then, when the operator has records to publish, the
// records. verbose adds the records a ready proxy's primary already serves.
func printParentSyncReport(w io.Writer, zone string, r *tdns.ParentSyncReport, todo []string, verbose bool) {
	var rows []string
	row := func(label, value string) { rows = append(rows, statusRow(label, value)...) }

	fmt.Fprintf(w, "%s (%s)\n", zone, r.Role)

	parent := r.Parent
	if parent == "" {
		parent = "(unknown)"
	}
	switch {
	case r.PlanError != "":
		row("parent", parent+"; DSYNC discovery failed: "+r.PlanError)
	case r.PlanNote != "":
		row("parent", parent)
		row("schemes", "none evaluated: "+r.PlanNote)
	default:
		if r.Validated {
			row("parent", parent+", DSYNC validated")
		} else {
			row("parent", parent+", DSYNC not validated")
		}
		for _, s := range r.Schemes {
			if s.Usable {
				row(s.Scheme, "usable: "+s.Target)
			} else {
				row(s.Scheme, "skipped: "+s.Reason)
			}
		}
	}

	var blocks [][]string
	if u := r.Update; u != nil {
		if r.Role == "parentsync-proxy" {
			blocks = proxyUpdateRows(u, row, verbose)
		} else {
			childUpdateRows(u, row)
		}
		switch {
		case u.ParentKeyState != "":
			state := strings.ToLower(u.ParentKeyState)
			if !u.ParentKeyAuthenticated {
				state += " (not authenticated)"
			}
			row("keystate", state)
		case u.ParentKeyError != "":
			row("keystate", u.ParentKeyError)
		}
	}

	if n := r.Notify; n != nil {
		signed := "signed"
		if !n.Signed {
			signed = "unsigned"
		}
		row("signals", fmt.Sprintf("zone is %s; CDS: %s, CSYNC: %s",
			signed, yesNo(n.PublishesCDS), yesNo(n.PublishesCSYNC)))
	}
	if a := r.Api; a != nil {
		cred := "configured"
		if !a.CredentialConfigured {
			cred = "none usable (parentsync.api.credentials)"
		}
		if a.AllowInsecure {
			cred += "; allow-insecure is set"
		}
		row("credential", cred)
	}

	switch d := r.Delegation; {
	case d == nil:
		row("delegation", "could not compare: "+r.DelegationError)
	case d.InSync:
		row("delegation", "in sync")
	default:
		row("delegation", "not in sync:")
		rows = append(rows, delegationChangeLines(*d, "    ")...)
		rows = append(rows, unreadLines(*d, "    ")...)
	}

	if r.Warning != "" {
		row("warning", r.Warning)
	}
	for _, t := range todo {
		row("todo", t)
	}
	writeLines(w, rows)

	for _, b := range blocks {
		fmt.Fprintln(w)
		writeLines(w, b)
	}
}

// proxyUpdateRows adds the UPDATE rows for a parentsync-proxy zone, and
// returns the record blocks to print under the rows.
func proxyUpdateRows(u *tdns.ParentSyncUpdateReport, row func(string, string), verbose bool) [][]string {
	if u.ProxyError != "" {
		row("key", "unknown: "+u.ProxyError)
		return nil
	}
	records := func(heading string) []string {
		out := []string{heading}
		for _, rr := range u.ProxyRecords {
			out = append(out, zoneFileLines(rr)...)
		}
		if u.ProxyRFC3597 != "" {
			out = append(out, "; the same HSYNCPARAM in RFC 3597 form:")
			out = append(out, zoneFileLines(u.ProxyRFC3597)...)
		}
		return out
	}
	if len(u.ProxyRecords) == 0 {
		row("key", "none generated yet")
		return nil
	}
	switch u.ProxyState {
	case "ready":
		row("key", fmt.Sprintf("%d, published at the primary", u.ActiveKeyID))
		if verbose {
			return [][]string{records("published at the primary's apex:")}
		}
		return nil
	case "waiting-for-key":
		// The scheme row says it is waiting; the records say for what.
		return [][]string{records("publish at the primary's apex:")}
	case "foreign-key":
		row("key", fmt.Sprintf("%d, not at the apex; a KEY the agent does not hold is", u.ActiveKeyID))
		foreign := []string{"remove from the primary's apex:"}
		for _, rr := range u.ProxyForeignKeys {
			foreign = append(foreign, zoneFileLines(rr)...)
		}
		return [][]string{foreign, records("publish at the primary's apex instead:")}
	default:
		row("key", fmt.Sprintf("%d (%s)", u.ActiveKeyID, u.ProxyState))
		return nil
	}
}

// childUpdateRows adds the UPDATE row for a zone syncing its own delegation:
// its SIG(0) key, and whether the KEY is at the apex.
func childUpdateRows(u *tdns.ParentSyncUpdateReport, row func(string, string)) {
	if !u.HaveActiveKey {
		row("key", "no active SIG(0) key")
		return
	}
	published := false
	ids := make([]string, 0, len(u.ApexKeyIDs))
	for _, id := range u.ApexKeyIDs {
		if id == u.ActiveKeyID {
			published = true
		}
		ids = append(ids, fmt.Sprint(id))
	}
	switch {
	case published:
		row("key", fmt.Sprintf("%d at the apex", u.ActiveKeyID))
	case len(ids) == 0:
		row("key", fmt.Sprintf("%d; the apex has no KEY", u.ActiveKeyID))
	default:
		row("key", fmt.Sprintf("%d; the apex has KEY %s, not this one", u.ActiveKeyID, strings.Join(ids, ", ")))
	}
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
