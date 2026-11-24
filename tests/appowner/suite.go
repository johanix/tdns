/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The suite: its callers, one verdict line per check, and the state checks a
 * verdict rests on. A refusal passes only if it is refused for the reason
 * the check names AND the audit view shows nothing changed; an accepted
 * request passes only if the audit view shows the change.
 */
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type suite struct {
	o     options
	tr    *transcript
	app1  *client
	app2  *client
	op    *client
	key   *client
	au    audit
	adm   ncli
	pass  int
	fail  int
	notes int
	fails []string
	// secrets are the TSIG secrets the suite made, by key name. Never
	// printed; a listing is searched for them.
	secrets map[string]string
}

func newSuite(o options) (*suite, error) {
	tr, err := openTranscript(o.Transcript)
	if err != nil {
		return nil, err
	}
	s := &suite{o: o, tr: tr, secrets: map[string]string{}}
	mk := func(who string) (*client, error) {
		return newCertClient(who, o.API, filepath.Join(o.Clients, who+".crt"), filepath.Join(o.Clients, who+".key"), o.Pin, tr)
	}
	if s.app1, err = mk("app1"); err != nil {
		return nil, err
	}
	if s.app2, err = mk("app2"); err != nil {
		return nil, err
	}
	if s.op, err = mk("op"); err != nil {
		return nil, err
	}
	s.key = newKeyClient(o.API, o.ApiKey, o.Pin, tr)
	s.au = audit{c: newSocketClient(o.Socket, o.DaemonConfig, tr)}
	s.adm = ncli{bin: o.Ncli, cfg: o.NcliConfig, tr: tr}
	return s, nil
}

func (s *suite) close() { s.tr.close() }

// secret makes a new HMAC-SHA256 TSIG secret for the key name.
func (s *suite) secret(name string) string {
	b := make([]byte, 32)
	rand.Read(b)
	v := base64.StdEncoding.EncodeToString(b)
	s.secrets[name] = v
	return v
}

// verdict prints one check's line, and on a FAIL what was seen, indented.
func (s *suite) verdict(id, name string, ok bool, reason string, detail ...string) bool {
	s.tr.note("%s %s %s: %s", map[bool]string{true: "PASS", false: "FAIL"}[ok], id, name, reason)
	if ok {
		s.pass++
		fmt.Printf("PASS  %-5s %s: %s\n", id, name, reason)
		return true
	}
	s.fail++
	s.fails = append(s.fails, id+" "+name)
	fmt.Printf("FAIL  %-5s %s: %s\n", id, name, reason)
	for _, d := range detail {
		for _, l := range strings.Split(strings.TrimRight(d, "\n"), "\n") {
			fmt.Printf("            | %s\n", l)
		}
	}
	return false
}

// state is a check of what the daemon holds: "" when it is as expected,
// else what is wrong.
type state func() string

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return oneLine(l, 120)
}

func (s *suite) states(states []state) string {
	var bad []string
	for _, st := range states {
		if st == nil {
			continue
		}
		if why := st(); why != "" {
			bad = append(bad, why)
		}
	}
	return strings.Join(bad, "; ")
}

// ok: the request must be accepted, and then every state must hold.
func (s *suite) ok(id, name string, o outcome, states ...state) bool {
	if !o.OK {
		return s.verdict(id, name, false, fmt.Sprintf("refused (HTTP %d), expected to work", o.HTTP), o.Msg)
	}
	if bad := s.states(states); bad != "" {
		return s.verdict(id, name, false, "accepted, but "+bad, o.Msg)
	}
	msg := firstLine(o.Msg)
	if msg == "" {
		msg = "done"
	}
	return s.verdict(id, name, true, "accepted: "+msg)
}

// refused: the request must be refused for a reason that contains one of
// want, and then every state must hold (that is, nothing changed).
func (s *suite) refused(id, name string, o outcome, want []string, states ...state) bool {
	if o.OK {
		bad := s.states(states)
		if bad != "" {
			bad = "; and " + bad
		}
		return s.verdict(id, name, false, "ACCEPTED, expected a refusal"+bad, o.Msg)
	}
	matched := len(want) == 0
	for _, w := range want {
		if strings.Contains(o.Msg, w) {
			matched = true
			break
		}
	}
	if !matched {
		return s.verdict(id, name, false, fmt.Sprintf("refused (HTTP %d), but not for the expected reason (%q)", o.HTTP, strings.Join(want, `" or "`)), o.Msg)
	}
	if bad := s.states(states); bad != "" {
		return s.verdict(id, name, false, "refused, but the state changed: "+bad, o.Msg)
	}
	return s.verdict(id, name, true, fmt.Sprintf("refused (HTTP %d): %s", o.HTTP, firstLine(o.Msg)))
}

// expect records a check that is decided by the suite itself.
func (s *suite) expect(id, name string, ok bool, reason string, detail ...string) bool {
	return s.verdict(id, name, ok, reason, detail...)
}

// holds: every state must hold now; reason says what that shows.
func (s *suite) holds(id, name, reason string, states ...state) bool {
	if bad := s.states(states); bad != "" {
		return s.verdict(id, name, false, bad)
	}
	return s.verdict(id, name, true, reason)
}

// note records what the daemon did where the design does not say what it
// should: no verdict, a line for the reader (README.md lists the questions).
func (s *suite) note(id, text string) {
	s.notes++
	s.tr.note("NOTE %s %s", id, text)
	fmt.Printf("NOTE  %-5s %s\n", id, text)
}

func (s *suite) summary() int {
	fmt.Printf("\n%d checks: %d PASS, %d FAIL", s.pass+s.fail, s.pass, s.fail)
	if s.notes > 0 {
		fmt.Printf(" (and %d NOTE: the design does not decide those cases)", s.notes)
	}
	fmt.Printf("\n")
	if s.fail == 0 {
		return 0
	}
	fmt.Printf("FAILED:\n")
	for _, f := range s.fails {
		fmt.Printf("  %s\n", f)
	}
	return 1
}

// ---- states, read through the audit view ----------------------------------

func (s *suite) zoneOwner(zone, owner string) state {
	return func() string {
		got, ok, err := s.au.owner(zone)
		switch {
		case err != nil:
			return err.Error()
		case !ok:
			return zone + " is not served"
		case got != owner:
			return fmt.Sprintf("%s has API owner %q, not %q", zone, got, owner)
		}
		return ""
	}
}

func (s *suite) zoneAbsent(zone string) state {
	return func() string {
		_, ok, err := s.au.owner(zone)
		switch {
		case err != nil:
			return err.Error()
		case ok:
			return zone + " is served"
		}
		return ""
	}
}

func (s *suite) primariesAre(zone, want string) state {
	return func() string {
		got, err := s.au.primaries(zone)
		switch {
		case err != nil:
			return err.Error()
		case got != want:
			return fmt.Sprintf("%s primaries are %s, not %s", zone, got, want)
		}
		return ""
	}
}

func (s *suite) tsigOwner(name, owner string) state {
	return func() string {
		keys, err := s.au.tsig()
		if err != nil {
			return err.Error()
		}
		k, ok := keys[name]
		switch {
		case !ok:
			return "TSIG key " + name + " is not in the keystore"
		case k.Owner != owner:
			return fmt.Sprintf("TSIG key %s has API owner %q, not %q", name, k.Owner, owner)
		}
		return ""
	}
}

func (s *suite) tsigAbsent(name string) state {
	return func() string {
		keys, err := s.au.tsig()
		if err != nil {
			return err.Error()
		}
		if _, ok := keys[name]; ok {
			return "TSIG key " + name + " is still in the keystore"
		}
		return ""
	}
}

// tsigSecretKept: the key still has the secret the suite gave it.
func (s *suite) tsigSecretKept(name string) state {
	return func() string {
		got, err := s.au.tsigSecret(name)
		if err != nil {
			return err.Error()
		}
		if got != s.secrets[name] {
			return "TSIG key " + name + " has another secret now"
		}
		return ""
	}
}

func (s *suite) tsigCount(n int) state {
	return func() string {
		keys, err := s.au.tsig()
		if err != nil {
			return err.Error()
		}
		if len(keys) != n {
			return fmt.Sprintf("the keystore has %d TSIG keys, not %d", len(keys), n)
		}
		return ""
	}
}

// dnssecIDs: zone has exactly these DNSSEC key IDs (none for nil).
func (s *suite) dnssecIDs(zone string, want []int) state {
	return func() string {
		m, err := s.au.dnssec()
		if err != nil {
			return err.Error()
		}
		if !slices.Equal(m[zone], want) {
			return fmt.Sprintf("%s has DNSSEC keys %v, not %v", zone, m[zone], want)
		}
		return ""
	}
}

func (s *suite) dnssecStateIs(zone string, id int, want string) state {
	return func() string {
		got, err := s.au.dnssecState(zone, id)
		switch {
		case err != nil:
			return err.Error()
		case got != want:
			return fmt.Sprintf("%s key %d is in state %q, not %q", zone, id, got, want)
		}
		return ""
	}
}

func (s *suite) sig0IDs(zone string, want []int) state {
	return func() string {
		m, err := s.au.sig0()
		if err != nil {
			return err.Error()
		}
		if !slices.Equal(m[zone], want) {
			return fmt.Sprintf("%s has SIG(0) keys %v, not %v", zone, m[zone], want)
		}
		return ""
	}
}

func (s *suite) dnssecCount(zone string, n int) state {
	return func() string {
		m, err := s.au.dnssec()
		if err != nil {
			return err.Error()
		}
		if len(m[zone]) != n {
			return fmt.Sprintf("%s has %d DNSSEC keys, not %d", zone, len(m[zone]), n)
		}
		return ""
	}
}

func (s *suite) sig0Count(zone string, n int) state {
	return func() string {
		m, err := s.au.sig0()
		if err != nil {
			return err.Error()
		}
		if len(m[zone]) != n {
			return fmt.Sprintf("%s has %d SIG(0) keys, not %d", zone, len(m[zone]), n)
		}
		return ""
	}
}

// nothingAt: zone publishes nothing at name.
func (s *suite) nothingAt(zone, name string) state {
	return func() string {
		rr, err := s.au.rrsets(zone, name)
		if err != nil {
			return err.Error()
		}
		if len(rr) > 0 {
			return fmt.Sprintf("%s publishes %v at %s", zone, rr, name)
		}
		return ""
	}
}

// publishes: zone has an RR of type t at name whose text contains want.
func (s *suite) publishes(zone, name, t, want string) state {
	return func() string {
		rr, err := s.au.rrsets(zone, name)
		if err != nil {
			return err.Error()
		}
		for _, r := range rr[t] {
			if strings.Contains(r, want) {
				return ""
			}
		}
		return fmt.Sprintf("%s has no %s %s %s (has %v)", zone, name, t, want, rr)
	}
}

func (s *suite) member(cat, zone string, want bool) state {
	return func() string {
		ms, err := s.au.members(cat)
		if err != nil {
			return err.Error()
		}
		if slices.Contains(ms, zone) != want {
			return fmt.Sprintf("catalog %s members are %v", cat, ms)
		}
		return ""
	}
}

// memberGroup: zone, a member of catalog cat, has (or has not) group.
func (s *suite) memberGroup(cat, zone, group string, want bool) state {
	return func() string {
		gs, err := s.au.memberGroups(cat, zone)
		if err != nil {
			return err.Error()
		}
		if slices.Contains(gs, group) != want {
			return fmt.Sprintf("%s in catalog %s has groups %v", zone, cat, gs)
		}
		return ""
	}
}

func (s *suite) polling(want bool) state {
	return func() string {
		on, err := s.au.scannerPolling()
		if err != nil {
			return err.Error()
		}
		if on != want {
			return fmt.Sprintf("the scanner's poll scan is %v, was %v", on, want)
		}
		return ""
	}
}

// query asks the daemon's DNS service for name/qtype: the rcode and any A
// records' addresses, as one string.
func (s *suite) query(name string, qtype uint16) string {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	c := &dns.Client{Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, s.o.DNS)
	if err != nil {
		return "no answer (" + err.Error() + ")"
	}
	out := []string{dns.RcodeToString[r.Rcode]}
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return strings.Join(out, " ")
}

// tsigOf is the TSIG keys the audit view says owner has.
func (s *suite) tsigOf(owner string) []string {
	ks, err := s.au.tsig()
	if err != nil {
		return []string{"(audit: " + err.Error() + ")"}
	}
	var out []string
	for name, k := range ks {
		if k.Owner == owner {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ---- small helpers ----------------------------------------------------------

func sorted(xs []string) []string {
	out := slices.Clone(xs)
	sort.Strings(out)
	return out
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sameSet says whether got and want hold the same names.
func sameSet(got, want []string) bool {
	g := slices.Clone(got)
	w := slices.Clone(want)
	sort.Strings(g)
	sort.Strings(w)
	return slices.Equal(g, w)
}

func list(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	return strings.Join(xs, " ")
}

// intersect is the names of a that are in b.
func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}
