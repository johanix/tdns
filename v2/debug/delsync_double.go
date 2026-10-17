/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// The adversarial receiver double (design doc §6).
//
// A large part of the delsync matrix cannot be tested against a well-behaved
// parent, because a CORRECT tdns-auth will never do the things the tests need
// to observe: go silent so the child's retry/backoff schedule is measurable
// (D1), answer BADKEY forever so the re-bootstrap bound is provable (D3), or
// return a FORGED or UNSIGNED KeyState response so the child's verification can
// be shown to reject it (G3/G4). Those cases need a receiver that misbehaves on
// command, which is what this is.
//
// Two design commitments make it useful as an oracle rather than just a stub:
//
//  1. Everything is JOURNALED. Assertions read the journal, not the double's
//     internal state — "how many attempts arrived, how far apart, and how many
//     of them were bootstrap ceremonies" is exactly the D1/D3 question, and it
//     is answerable only from the receiving end.
//  2. It is SCRIPTED declaratively (YAML), so a scenario states the receiver's
//     behaviour as data rather than as a bespoke handler. Rules match in order
//     and can be exhausted with `times`, which is what expresses "BADKEY once,
//     then accept" (D2) as distinct from "BADKEY forever" (D3).
//
// It deliberately does NOT validate anything: it is not a tdns-auth substitute,
// it answers whatever the script says. Signature checking of the requests it
// receives is the real server's job; the double's job is to be predictably
// wrong.

// --- script ------------------------------------------------------------------

// DoubleMatch selects which requests a rule applies to. Zero-valued fields do
// not constrain, so an empty match matches everything.
type DoubleMatch struct {
	// Opcode is "UPDATE" or "QUERY" (case-insensitive); empty matches any.
	Opcode string `yaml:"opcode"`
	// KeyState, when true, requires the request to carry a KeyState EDNS(0)
	// option. This is what separates a KeyState inquiry from an ordinary query,
	// since both are OpcodeQuery.
	KeyState bool `yaml:"keystate"`
	// Qname matches the question name (queries) or the zone name (updates),
	// case-insensitively. A leading "*." matches any name in that subtree.
	Qname string `yaml:"qname"`
	// Ceremony, when non-nil, requires the UPDATE's Update section to be (or
	// not to be) a bootstrap DEL-ANY-KEY + ADD KEY ceremony. This is how D3
	// distinguishes a re-bootstrap from an ordinary delegation UPDATE.
	Ceremony *bool `yaml:"ceremony"`
}

// DoubleRespond is what the double does when a rule matches.
type DoubleRespond struct {
	// Rcode is a mnemonic ("NOERROR", "BADKEY", "REFUSED", ...) as spelled by
	// dns.StringToRcode. Empty means NOERROR.
	Rcode string `yaml:"rcode"`
	// Drop discards the request without answering — the silent-parent case that
	// makes the child's timeout and backoff schedule observable (D1).
	Drop bool `yaml:"drop"`
	// KeyState, when non-nil, attaches a KeyState option carrying this
	// KEY-STATE value. KeyData/ExtraText are optional companions.
	KeyState  *uint8 `yaml:"keystate"`
	KeyData   *uint8 `yaml:"keydata"`
	ExtraText string `yaml:"extra_text"`
	// Sign controls the SIG(0) on the response:
	//   "correct" (default when a KeyState option is attached) — sign with the
	//             receiver's own key, as a conforming receiver must;
	//   "none"    — send the KeyState option UNSIGNED (G4);
	//   "wrong-key" — sign with a key the child does not expect (G3 forgery).
	Sign string `yaml:"sign"`
	// EDE, when non-nil, attaches an Extended DNS Error with this code.
	EDE *uint16 `yaml:"ede"`
	// DelayMs delays the response, for latency/timeout-boundary cases.
	DelayMs int `yaml:"delay_ms"`
}

// DoubleRule is one scripted behaviour. Rules are evaluated in order and the
// first match wins.
type DoubleRule struct {
	Match   DoubleMatch   `yaml:"match"`
	Respond DoubleRespond `yaml:"respond"`
	// Times limits how often this rule may fire; 0 means unlimited. An
	// exhausted rule is skipped, so later rules take over — that is how
	// "BADKEY once, then NOERROR" is expressed.
	Times int `yaml:"times"`

	fired int // guarded by Double.mu
}

// DoubleScript is the ordered rule list. A request matching no rule gets the
// default response (NOERROR, nothing attached).
type DoubleScript struct {
	Rules []DoubleRule `yaml:"rules"`
}

// ParseDoubleScript reads a script from YAML.
func ParseDoubleScript(buf []byte) (DoubleScript, error) {
	var s DoubleScript
	if err := yaml.Unmarshal(buf, &s); err != nil {
		return DoubleScript{}, fmt.Errorf("parsing double script: %w", err)
	}
	for i, r := range s.Rules {
		if r.Respond.Rcode != "" {
			if _, ok := dns.StringToRcode[strings.ToUpper(r.Respond.Rcode)]; !ok {
				return DoubleScript{}, fmt.Errorf("rule %d: unknown rcode %q", i, r.Respond.Rcode)
			}
		}
		switch strings.ToLower(r.Respond.Sign) {
		case "", "correct", "none", "wrong-key":
		default:
			return DoubleScript{}, fmt.Errorf("rule %d: unknown sign mode %q (want correct|none|wrong-key)", i, r.Respond.Sign)
		}
		if op := strings.ToUpper(r.Match.Opcode); op != "" && op != "UPDATE" && op != "QUERY" {
			return DoubleScript{}, fmt.Errorf("rule %d: unknown opcode %q (want UPDATE|QUERY)", i, r.Match.Opcode)
		}
	}
	return s, nil
}

// --- journal -----------------------------------------------------------------

// DoubleJournalEntry is one observed request and what the double did with it.
// The journal is the assertion surface: retry counts and intervals (D1),
// "exactly one re-bootstrap" (D3), and transport (C1) are all read from here.
type DoubleJournalEntry struct {
	At        time.Time `json:"at"`
	Transport string    `json:"transport"` // "udp" | "tcp"
	Opcode    string    `json:"opcode"`    // "UPDATE" | "QUERY" | ...
	Qname     string    `json:"qname"`
	// Signer/KeyID come from the SIG(0) RR on the request, when present. They
	// are read straight off the wire and NOT verified — the double does not
	// authenticate, it observes.
	Signer string `json:"signer,omitempty"`
	KeyID  uint16 `json:"key_id,omitempty"`
	Signed bool   `json:"signed"`
	// UpdateSection is the rendered Update section of an UPDATE, which is what
	// makes the DEL-ANY-KEY + ADD KEY ceremony assertable on the wire (E1).
	UpdateSection []string `json:"update_section,omitempty"`
	Ceremony      bool     `json:"ceremony"`
	// KeyStateReq is the KEY-STATE value the request carried, when it carried a
	// KeyState option (nil otherwise) — lets A2 assert what was actually sent.
	KeyStateReq *uint8 `json:"keystate_req,omitempty"`

	RespondedRcode string `json:"responded_rcode,omitempty"`
	Dropped        bool   `json:"dropped"`
	RuleIndex      int    `json:"rule_index"` // -1 when no rule matched
}

// --- the double --------------------------------------------------------------

// DoubleConfig parameterizes StartDouble.
//
// Note this takes a config struct rather than the design doc's positional
// (listen, script, signer): the forgery case needs a SECOND key, since "signed
// by the wrong key" cannot be expressed with only the receiver's own key, and
// G3 is one of the cases the double exists for.
type DoubleConfig struct {
	// Listen is addr:port. Port 0 picks a free port; use Addr() to read it back.
	Listen string
	Script DoubleScript
	// Signer is the receiver's own SIG(0) key, used for `sign: correct`.
	Signer *Sig0Signer
	// WrongSigner is any other key, used for `sign: wrong-key` (G3). A rule
	// requesting wrong-key without one configured is a setup error.
	WrongSigner *Sig0Signer
}

// Double is a running adversarial receiver. It serves UDP and TCP on the same
// port, because which transport a request arrives on is itself under test
// (D-2a says delegation UPDATEs go over TCP) and a double that listened on only
// one would silently pass that check by making the other impossible.
type Double struct {
	cfg DoubleConfig

	mu      sync.Mutex
	script  DoubleScript
	journal []DoubleJournalEntry

	udp, tcp *dns.Server
	addr     string
	wg       sync.WaitGroup
	closeOnce sync.Once
}

// StartDouble binds and starts the double. It returns once both listeners are
// accepting, so a caller may send immediately without racing startup.
func StartDouble(ctx context.Context, cfg DoubleConfig) (*Double, error) {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}

	// Bind TCP first so a port-0 request resolves to a concrete port, then bind
	// UDP to that same port. Doing it in the other order would leave the TCP
	// bind able to fail on an already-taken port with no way to renegotiate.
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("double: listen tcp %s: %w", cfg.Listen, err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("double: listen udp %s: %w", ln.Addr().String(), err)
	}

	d := &Double{cfg: cfg, script: cfg.Script, addr: ln.Addr().String()}

	// tdns's own accept func: the miekg default answers NOTIMP to the UPDATE
	// opcode before any handler runs, which would make every UPDATE case
	// untestable.
	d.tcp = &dns.Server{Listener: ln, Net: "tcp", MsgAcceptFunc: tdns.MsgAcceptFunc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { d.handle(w, r, "tcp") })}
	d.udp = &dns.Server{PacketConn: pc, Net: "udp", MsgAcceptFunc: tdns.MsgAcceptFunc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { d.handle(w, r, "udp") })}

	tcpUp, udpUp := make(chan struct{}), make(chan struct{})
	d.tcp.NotifyStartedFunc = func() { close(tcpUp) }
	d.udp.NotifyStartedFunc = func() { close(udpUp) }

	d.wg.Add(2)
	go func() { defer d.wg.Done(); _ = d.tcp.ActivateAndServe() }()
	go func() { defer d.wg.Done(); _ = d.udp.ActivateAndServe() }()

	select {
	case <-tcpUp:
	case <-time.After(5 * time.Second):
		d.Close()
		return nil, fmt.Errorf("double: tcp listener did not start")
	}
	select {
	case <-udpUp:
	case <-time.After(5 * time.Second):
		d.Close()
		return nil, fmt.Errorf("double: udp listener did not start")
	}

	// Tie the lifetime to ctx so a scenario that returns early does not leak it.
	go func() {
		<-ctx.Done()
		d.Close()
	}()

	return d, nil
}

// Addr returns the actual addr:port being served (useful with port 0).
func (d *Double) Addr() string { return d.addr }

// Journal returns a copy of the observed requests, oldest first.
func (d *Double) Journal() []DoubleJournalEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]DoubleJournalEntry, len(d.journal))
	copy(out, d.journal)
	return out
}

// Close stops both listeners. Safe to call more than once.
func (d *Double) Close() error {
	d.closeOnce.Do(func() {
		if d.tcp != nil {
			_ = d.tcp.Shutdown()
		}
		if d.udp != nil {
			_ = d.udp.Shutdown()
		}
		d.wg.Wait()
	})
	return nil
}

// --- request handling ---------------------------------------------------------

func (d *Double) handle(w dns.ResponseWriter, r *dns.Msg, transport string) {
	entry := describeRequest(r, transport)

	rule, idx := d.pickRule(r, entry)
	entry.RuleIndex = idx

	resp := DoubleRespond{}
	if rule != nil {
		resp = rule.Respond
	}

	if resp.DelayMs > 0 {
		time.Sleep(time.Duration(resp.DelayMs) * time.Millisecond)
	}

	if resp.Drop {
		entry.Dropped = true
		d.record(entry)
		return // silence: the D1 case
	}

	m := d.buildResponse(r, resp)
	entry.RespondedRcode = dns.RcodeToString[m.Rcode]
	d.record(entry)
	_ = w.WriteMsg(m)
}

// pickRule returns the first unexhausted matching rule and its index, bumping
// its fire count. Returns (nil, -1) when nothing matches.
func (d *Double) pickRule(r *dns.Msg, e DoubleJournalEntry) (*DoubleRule, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.script.Rules {
		rule := &d.script.Rules[i]
		if rule.Times > 0 && rule.fired >= rule.Times {
			continue // exhausted; fall through to a later rule
		}
		if !matchRule(rule.Match, r, e) {
			continue
		}
		rule.fired++
		return rule, i
	}
	return nil, -1
}

func matchRule(m DoubleMatch, r *dns.Msg, e DoubleJournalEntry) bool {
	if op := strings.ToUpper(m.Opcode); op != "" && op != e.Opcode {
		return false
	}
	if m.KeyState && e.KeyStateReq == nil {
		return false
	}
	if m.Ceremony != nil && *m.Ceremony != e.Ceremony {
		return false
	}
	if m.Qname != "" && !qnameMatches(m.Qname, e.Qname) {
		return false
	}
	return true
}

// qnameMatches supports an exact name or a "*.zone." subtree wildcard.
func qnameMatches(pattern, name string) bool {
	pattern, name = strings.ToLower(dns.Fqdn(pattern)), strings.ToLower(name)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".zone."
		return strings.HasSuffix(name, suffix) || name == suffix[1:]
	}
	return pattern == name
}

func (d *Double) record(e DoubleJournalEntry) {
	d.mu.Lock()
	d.journal = append(d.journal, e)
	d.mu.Unlock()
}

// describeRequest extracts everything the journal and the matcher need from an
// incoming message. It reads the SIG(0) off the wire WITHOUT verifying it: the
// double observes, it does not authenticate.
func describeRequest(r *dns.Msg, transport string) DoubleJournalEntry {
	e := DoubleJournalEntry{
		At:        time.Now(),
		Transport: transport,
		Opcode:    dns.OpcodeToString[r.Opcode],
		RuleIndex: -1,
	}
	if len(r.Question) > 0 {
		e.Qname = strings.ToLower(r.Question[0].Name)
	}

	for _, rr := range r.Extra {
		if sig, ok := rr.(*dns.SIG); ok {
			e.Signed = true
			e.Signer = strings.ToLower(sig.SignerName)
			e.KeyID = sig.KeyTag
			break
		}
	}

	if opt := r.IsEdns0(); opt != nil {
		if ks, found := edns0.ExtractKeyStateOption(opt); found {
			state := ks.KeyState
			e.KeyStateReq = &state
		}
	}

	if r.Opcode == dns.OpcodeUpdate {
		for _, rr := range r.Ns {
			e.UpdateSection = append(e.UpdateSection, rr.String())
		}
		e.Ceremony = isBootstrapCeremony(r.Ns)
	}
	return e
}

// isBootstrapCeremony reports whether an Update section is the self-signed
// bootstrap ceremony of draft-ietf-dnsop-delegation-mgmt-via-ddns-02:
// "DEL <child> ANY KEY" plus "ADD <child> KEY" for the same owner.
//
// It classifies on the RR HEADER's Class+Rrtype, not the Go type, because a
// wire "DEL <name> ANY KEY" is a class-ANY rdlength-0 record that miekg/dns
// unpacks as *dns.ANY with KEY in the header — matching how the real receiver's
// bootstrapCeremony() decides. Counting these in the journal is what makes
// "exactly one re-bootstrap" (D3) assertable.
func isBootstrapCeremony(ns []dns.RR) bool {
	var addName, delName string
	for _, rr := range ns {
		h := rr.Header()
		switch {
		case h.Class == dns.ClassINET && h.Rrtype == dns.TypeKEY:
			if addName != "" {
				return false // more than one ADD KEY
			}
			addName = strings.ToLower(h.Name)
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeKEY:
			if delName != "" {
				return false // more than one DEL ANY KEY
			}
			delName = strings.ToLower(h.Name)
		default:
			return false // anything else disqualifies it
		}
	}
	// The ceremony is specifically the DEL+ADD pair for one owner. A bare ADD
	// is an ordinary key upload, not a re-bootstrap, and must not be counted.
	return addName != "" && delName != "" && addName == delName
}

// buildResponse assembles the reply the script asked for.
func (d *Double) buildResponse(r *dns.Msg, resp DoubleRespond) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)

	rcode := dns.RcodeSuccess
	if resp.Rcode != "" {
		if rc, ok := dns.StringToRcode[strings.ToUpper(resp.Rcode)]; ok {
			rcode = rc
		}
	}

	// An OPT RR is mandatory before setting an extended rcode: values above 15
	// do not fit the 4-bit header field, and miekg/dns refuses to pack such a
	// message without an OPT to carry the upper bits — the response would be
	// silently dropped instead of arriving as BADKEY, which is precisely the
	// case D2/D3 depend on.
	if rcode > 0xF || resp.EDE != nil || resp.KeyState != nil {
		m.SetEdns0(4096, false)
	}
	m.Rcode = rcode

	if resp.EDE != nil {
		edns0.AttachEDEToResponse(m, *resp.EDE)
	}

	if resp.KeyState != nil {
		ks := &edns0.KeyStateOption{
			KeyID:     0,
			KeyState:  *resp.KeyState,
			ExtraText: resp.ExtraText,
		}
		if opt := r.IsEdns0(); opt != nil {
			if req, found := edns0.ExtractKeyStateOption(opt); found {
				ks.KeyID = req.KeyID // echo the inquired key, as a receiver must
			}
		}
		if resp.KeyData != nil {
			ks.KeyData = *resp.KeyData
		}
		edns0.AttachKeyStateToResponse(m, ks)
	}

	return d.signResponse(m, resp)
}

// signResponse applies the rule's SIG(0) mode. A KeyState response defaults to
// "correct", because keystate-03 requires the receiver to sign it; the other
// two modes exist to produce the responses a conforming receiver never would.
func (d *Double) signResponse(m *dns.Msg, resp DoubleRespond) *dns.Msg {
	mode := strings.ToLower(resp.Sign)
	if mode == "" {
		if resp.KeyState != nil {
			mode = "correct"
		} else {
			mode = "none"
		}
	}

	var signer *Sig0Signer
	switch mode {
	case "none":
		return m
	case "correct":
		signer = d.cfg.Signer
	case "wrong-key":
		signer = d.cfg.WrongSigner
	}
	if signer == nil {
		// No key for the requested mode. Send unsigned rather than failing the
		// exchange: a scenario asserting on the signature will fail with a
		// meaningful "response was not signed", not an opaque timeout.
		return m
	}

	signed, err := tdns.SignMsg(*m, signer.KeyName, signer.sak)
	if err != nil {
		return m
	}
	return signed
}
