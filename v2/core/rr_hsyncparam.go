/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package core

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Zone file syntax:
//   owner TTL CLASS HSYNCPARAM key1="val1" key2="val2" ...
//
// Example:
//   example.com. 3600 IN HSYNCPARAM nsmgmt="agent" parentsync="agent" audit="yes" signers="netnod,cloudflare"
//
// Known keys:
//   nsmgmt="owner|agent"                  - who manages the NS RRset
//   parentsync="owner|agent"              - who handles parent synchronisation
//   audit="yes|no"                        - whether audit is enabled
//   signers="label1,label2,..."           - comma-separated list of signer labels
//   pubkey                                - flag: providers publish SIG(0) KEY in zone
//   pubcds                                - flag: providers publish CDS/CDNSKEY in zone

func init() {
	RegisterHsyncparamRR()
}

// HSYNCPARAMKey is the type of keys used in the HSYNCPARAM RR.
type HSYNCPARAMKey uint16

const (
	HSYNCPARAM_NSMGMT     HSYNCPARAMKey = 0
	HSYNCPARAM_PARENTSYNC HSYNCPARAMKey = 1
	HSYNCPARAM_AUDIT      HSYNCPARAMKey = 2
	HSYNCPARAM_SIGNERS    HSYNCPARAMKey = 3
	HSYNCPARAM_PUBKEY     HSYNCPARAMKey = 4
	HSYNCPARAM_PUBCDS     HSYNCPARAMKey = 5
	hsyncparam_RESERVED   HSYNCPARAMKey = 65535
)

var hsyncparamKeyToStringMap = map[HSYNCPARAMKey]string{
	HSYNCPARAM_NSMGMT:     "nsmgmt",
	HSYNCPARAM_PARENTSYNC: "parentsync",
	HSYNCPARAM_AUDIT:      "audit",
	HSYNCPARAM_SIGNERS:    "signers",
	HSYNCPARAM_PUBKEY:     "pubkey",
	HSYNCPARAM_PUBCDS:     "pubcds",
}

var hsyncparamStringToKeyMap = reverseHSYNCPARAMKeyMap(hsyncparamKeyToStringMap)

func reverseHSYNCPARAMKeyMap(m map[HSYNCPARAMKey]string) map[string]HSYNCPARAMKey {
	n := make(map[string]HSYNCPARAMKey, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}

func (key HSYNCPARAMKey) String() string {
	if x := hsyncparamKeyToStringMap[key]; x != "" {
		return x
	}
	if key == hsyncparam_RESERVED {
		return ""
	}
	return "key" + strconv.FormatUint(uint64(key), 10)
}

func hsyncparamStringToKey(s string) HSYNCPARAMKey {
	if strings.HasPrefix(s, "key") {
		a, err := strconv.ParseUint(s[3:], 10, 16)
		if err != nil || a == 65535 || s[3] == '0' || hsyncparamKeyToStringMap[HSYNCPARAMKey(a)] != "" {
			return hsyncparam_RESERVED
		}
		return HSYNCPARAMKey(a)
	}
	if key, ok := hsyncparamStringToKeyMap[s]; ok {
		return key
	}
	return hsyncparam_RESERVED
}

// ParentSync constants: who handles parent synchronisation.
// The mechanism (NOTIFY, UPDATE, etc.) is announced by the parent via DSYNC.
const (
	HsyncParentSyncOwner uint8 = 0 // zone owner handles parent sync
	HsyncParentSyncAgent uint8 = 1 // providers coordinate via leader election
)

var HsyncParentSyncToString = map[uint8]string{
	HsyncParentSyncOwner: "owner",
	HsyncParentSyncAgent: "agent",
}

var StringToHsyncParentSync = map[string]uint8{
	"owner": HsyncParentSyncOwner,
	"agent": HsyncParentSyncAgent,
}

// HSYNCPARAMKeyValue defines a key=value pair for the HSYNCPARAM RR type.
type HSYNCPARAMKeyValue interface {
	Key() HSYNCPARAMKey
	pack() ([]byte, error)
	unpack([]byte) error
	String() string
	parse(string) error
	copy() HSYNCPARAMKeyValue
	len() int
}

// HSYNCPARAM is a single RR per zone carrying zone-wide multi-provider policy as key=value pairs.
type HSYNCPARAM struct {
	Value []HSYNCPARAMKeyValue
}

func NewHSYNCPARAM() dns.PrivateRdata { return new(HSYNCPARAM) }

func RegisterHsyncparamRR() error {
	dns.PrivateHandle("HSYNCPARAM", TypeHSYNCPARAM, NewHSYNCPARAM)
	dns.TypeToString[TypeHSYNCPARAM] = "HSYNCPARAM"
	return nil
}

// makeHSYNCPARAMKeyValue returns the appropriate HSYNCPARAMKeyValue for a known key,
// an HSYNCPARAMLocal for unknown keys, or nil for reserved keys.
func makeHSYNCPARAMKeyValue(key HSYNCPARAMKey) HSYNCPARAMKeyValue {
	switch key {
	case HSYNCPARAM_NSMGMT:
		return new(HSYNCPARAMNSmgmt)
	case HSYNCPARAM_PARENTSYNC:
		return new(HSYNCPARAMParentSync)
	case HSYNCPARAM_AUDIT:
		return new(HSYNCPARAMAudit)
	case HSYNCPARAM_SIGNERS:
		return new(HSYNCPARAMSigners)
	case HSYNCPARAM_PUBKEY:
		return &HSYNCPARAMFlag{code: HSYNCPARAM_PUBKEY}
	case HSYNCPARAM_PUBCDS:
		return &HSYNCPARAMFlag{code: HSYNCPARAM_PUBCDS}
	case hsyncparam_RESERVED:
		return nil
	default:
		e := new(HSYNCPARAMLocal)
		e.KeyCode = key
		return e
	}
}

// --- Pack / Unpack helpers ---

func packHsyncparamData(pairs []HSYNCPARAMKeyValue, msg []byte, off int) (int, error) {
	pairs = cloneSlice(pairs)
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Key() < pairs[j].Key()
	})
	prev := hsyncparam_RESERVED
	for _, el := range pairs {
		if el.Key() == prev {
			return len(msg), errors.New("repeated HSYNCPARAM keys are not allowed")
		}
		prev = el.Key()
		packed, err := el.pack()
		if err != nil {
			return len(msg), err
		}
		off, err = packUint16(uint16(el.Key()), msg, off)
		if err != nil {
			return len(msg), errors.New("overflow packing HSYNCPARAM")
		}
		off, err = packUint16(uint16(len(packed)), msg, off)
		if err != nil || len(packed) > len(msg)-off {
			return len(msg), errors.New("overflow packing HSYNCPARAM")
		}
		copy(msg[off:off+len(packed)], packed)
		off += len(packed)
	}
	return off, nil
}

func unpackHsyncparamData(msg []byte, off int) ([]HSYNCPARAMKeyValue, int, error) {
	var xs []HSYNCPARAMKeyValue
	var code uint16
	var length uint16
	var err error
	for off < len(msg) {
		code, off, err = unpackUint16(msg, off)
		if err != nil {
			return nil, len(msg), errors.New("overflow unpacking HSYNCPARAM")
		}
		length, off, err = unpackUint16(msg, off)
		if err != nil || int(length) > len(msg)-off {
			return nil, len(msg), errors.New("overflow unpacking HSYNCPARAM")
		}
		e := makeHSYNCPARAMKeyValue(HSYNCPARAMKey(code))
		if e == nil {
			return nil, len(msg), errors.New("bad HSYNCPARAM key")
		}
		if err := e.unpack(msg[off : off+int(length)]); err != nil {
			return nil, len(msg), err
		}
		if len(xs) > 0 && e.Key() <= xs[len(xs)-1].Key() {
			return nil, len(msg), errors.New("HSYNCPARAM keys not in strictly increasing order")
		}
		xs = append(xs, e)
		off += int(length)
	}
	return xs, off, nil
}

// --- PrivateRdata interface ---

func (rr *HSYNCPARAM) Parse(s []string) error {
	// miekg/dns PrivateRR.parse() strips quotes and splits tokens, so
	// key="value" arrives as ["key=", "value"]. We rejoin those before
	// parsing key=value pairs.
	var tokens []string
	for i := 0; i < len(s); i++ {
		tok := s[i]
		if strings.HasSuffix(tok, "=") && i+1 < len(s) {
			// "key=" + "value" → "key=value"
			tok += s[i+1]
			i++
		}
		tokens = append(tokens, tok)
	}

	var xs []HSYNCPARAMKeyValue
	for _, tok := range tokens {
		idx := strings.IndexByte(tok, '=')
		var key, value string
		if idx < 0 {
			key = tok // bare key → boolean flag (SVCB semantics)
		} else if idx == 0 {
			return fmt.Errorf("HSYNCPARAM: empty key in %q", tok)
		} else {
			key, value = tok[:idx], tok[idx+1:]
		}

		kv := makeHSYNCPARAMKeyValue(hsyncparamStringToKey(key))
		if kv == nil {
			return fmt.Errorf("HSYNCPARAM: unknown key %q", key)
		}
		if err := kv.parse(value); err != nil {
			return err
		}
		xs = append(xs, kv)
	}

	rr.Value = xs
	return nil
}

func (rr *HSYNCPARAM) String() string {
	var s string
	for i, e := range rr.Value {
		if i > 0 {
			s += " "
		}
		if val := e.String(); val != "" {
			s += e.Key().String() + "=\"" + val + "\""
		} else {
			s += e.Key().String()
		}
	}
	return s
}

func (rr *HSYNCPARAM) Pack(buf []byte) (int, error) {
	off, err := packHsyncparamData(rr.Value, buf, 0)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *HSYNCPARAM) Unpack(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var off int
	var err error
	rr.Value, off, err = unpackHsyncparamData(buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *HSYNCPARAM) Copy(dest dns.PrivateRdata) error {
	d := dest.(*HSYNCPARAM)
	d.Value = make([]HSYNCPARAMKeyValue, len(rr.Value))
	for i, e := range rr.Value {
		d.Value[i] = e.copy()
	}
	return nil
}

func (rr *HSYNCPARAM) Len() int {
	l := 0
	for _, x := range rr.Value {
		l += 4 + int(x.len()) // 2 bytes key + 2 bytes length + value
	}
	return l
}

// --- Accessor helpers ---

// GetNSmgmt returns the nsmgmt value from the HSYNCPARAM record, defaulting to HsyncNSmgmtOWNER.
func (h *HSYNCPARAM) GetNSmgmt() uint8 {
	for _, kv := range h.Value {
		if v, ok := kv.(*HSYNCPARAMNSmgmt); ok {
			return v.Value
		}
	}
	return HsyncNSmgmtOWNER
}

// GetParentSync returns the parentsync value, defaulting to HsyncParentSyncOwner.
func (h *HSYNCPARAM) GetParentSync() uint8 {
	for _, kv := range h.Value {
		if v, ok := kv.(*HSYNCPARAMParentSync); ok {
			return v.Value
		}
	}
	return HsyncParentSyncOwner
}

// GetAudit returns the audit value, defaulting to 0 (no).
func (h *HSYNCPARAM) GetAudit() uint8 {
	for _, kv := range h.Value {
		if v, ok := kv.(*HSYNCPARAMAudit); ok {
			return v.Value
		}
	}
	return 0
}

// GetSigners returns the signers list, defaulting to empty.
func (h *HSYNCPARAM) GetSigners() []string {
	for _, kv := range h.Value {
		if v, ok := kv.(*HSYNCPARAMSigners); ok {
			return v.Signers
		}
	}
	return []string{}
}

// IsSignerLabel checks if the given label is listed in the signers.
func (h *HSYNCPARAM) IsSignerLabel(label string) bool {
	for _, s := range h.GetSigners() {
		if s == label {
			return true
		}
	}
	return false
}

// HasPubkey returns true if the pubkey flag is present.
func (h *HSYNCPARAM) HasPubkey() bool {
	for _, kv := range h.Value {
		if kv.Key() == HSYNCPARAM_PUBKEY {
			return true
		}
	}
	return false
}

// HasPubcds returns true if the pubcds flag is present.
func (h *HSYNCPARAM) HasPubcds() bool {
	for _, kv := range h.Value {
		if kv.Key() == HSYNCPARAM_PUBCDS {
			return true
		}
	}
	return false
}

// --- HSYNCPARAMNSmgmt: uint8 key=value for NS management mode ---

type HSYNCPARAMNSmgmt struct {
	Value uint8
}

func (*HSYNCPARAMNSmgmt) Key() HSYNCPARAMKey { return HSYNCPARAM_NSMGMT }

func (s *HSYNCPARAMNSmgmt) String() string {
	switch s.Value {
	case HsyncNSmgmtOWNER:
		return "owner"
	case HsyncNSmgmtAGENT:
		return "agent"
	default:
		return strconv.FormatUint(uint64(s.Value), 10)
	}
}

func (s *HSYNCPARAMNSmgmt) pack() ([]byte, error) {
	return []byte{s.Value}, nil
}

func (s *HSYNCPARAMNSmgmt) unpack(b []byte) error {
	if len(b) != 1 {
		return errors.New("dns: hsyncparam nsmgmt: value length is not 1")
	}
	s.Value = b[0]
	return nil
}

func (s *HSYNCPARAMNSmgmt) parse(b string) error {
	switch strings.ToLower(b) {
	case "owner":
		s.Value = HsyncNSmgmtOWNER
	case "agent":
		s.Value = HsyncNSmgmtAGENT
	default:
		return fmt.Errorf("dns: hsyncparam nsmgmt: unknown value %q (expected \"owner\" or \"agent\")", b)
	}
	return nil
}

func (s *HSYNCPARAMNSmgmt) len() int                 { return 1 }
func (s *HSYNCPARAMNSmgmt) copy() HSYNCPARAMKeyValue { return &HSYNCPARAMNSmgmt{Value: s.Value} }

// --- HSYNCPARAMParentSync: uint8 key=value for parent sync mode ---

type HSYNCPARAMParentSync struct {
	Value uint8
}

func (*HSYNCPARAMParentSync) Key() HSYNCPARAMKey { return HSYNCPARAM_PARENTSYNC }

func (s *HSYNCPARAMParentSync) String() string {
	if str, ok := HsyncParentSyncToString[s.Value]; ok {
		return str
	}
	return strconv.FormatUint(uint64(s.Value), 10)
}

func (s *HSYNCPARAMParentSync) pack() ([]byte, error) {
	return []byte{s.Value}, nil
}

func (s *HSYNCPARAMParentSync) unpack(b []byte) error {
	if len(b) != 1 {
		return errors.New("dns: hsyncparam parentsync: value length is not 1")
	}
	s.Value = b[0]
	return nil
}

func (s *HSYNCPARAMParentSync) parse(b string) error {
	v, ok := StringToHsyncParentSync[strings.ToLower(b)]
	if !ok {
		return fmt.Errorf("dns: hsyncparam parentsync: unknown value %q (expected \"owner\" or \"agent\")", b)
	}
	s.Value = v
	return nil
}

func (s *HSYNCPARAMParentSync) len() int { return 1 }
func (s *HSYNCPARAMParentSync) copy() HSYNCPARAMKeyValue {
	return &HSYNCPARAMParentSync{Value: s.Value}
}

// --- HSYNCPARAMAudit: uint8 key=value for audit flag ---

type HSYNCPARAMAudit struct {
	Value uint8
}

func (*HSYNCPARAMAudit) Key() HSYNCPARAMKey { return HSYNCPARAM_AUDIT }

func (s *HSYNCPARAMAudit) String() string {
	if s.Value == 1 {
		return "yes"
	}
	return "no"
}

func (s *HSYNCPARAMAudit) pack() ([]byte, error) {
	return []byte{s.Value}, nil
}

func (s *HSYNCPARAMAudit) unpack(b []byte) error {
	if len(b) != 1 {
		return errors.New("dns: hsyncparam audit: value length is not 1")
	}
	s.Value = b[0]
	return nil
}

func (s *HSYNCPARAMAudit) parse(b string) error {
	switch strings.ToLower(b) {
	case "yes":
		s.Value = 1
	case "no":
		s.Value = 0
	default:
		return fmt.Errorf("dns: hsyncparam audit: unknown value %q (expected \"yes\" or \"no\")", b)
	}
	return nil
}

func (s *HSYNCPARAMAudit) len() int                 { return 1 }
func (s *HSYNCPARAMAudit) copy() HSYNCPARAMKeyValue { return &HSYNCPARAMAudit{Value: s.Value} }

// --- HSYNCPARAMSigners: comma-separated list of signer labels ---

type HSYNCPARAMSigners struct {
	Signers []string
}

func (*HSYNCPARAMSigners) Key() HSYNCPARAMKey { return HSYNCPARAM_SIGNERS }

func (s *HSYNCPARAMSigners) String() string {
	return strings.Join(s.Signers, ",")
}

func (s *HSYNCPARAMSigners) pack() ([]byte, error) {
	return []byte(strings.Join(s.Signers, ",")), nil
}

func (s *HSYNCPARAMSigners) unpack(b []byte) error {
	if len(b) == 0 {
		s.Signers = []string{}
		return nil
	}
	s.Signers = strings.Split(string(b), ",")
	return nil
}

func (s *HSYNCPARAMSigners) parse(b string) error {
	if b == "" {
		s.Signers = []string{}
		return nil
	}
	parts := strings.Split(b, ",")
	signers := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			signers = append(signers, p)
		}
	}
	s.Signers = signers
	return nil
}

func (s *HSYNCPARAMSigners) len() int {
	return len(strings.Join(s.Signers, ","))
}

func (s *HSYNCPARAMSigners) copy() HSYNCPARAMKeyValue {
	return &HSYNCPARAMSigners{Signers: cloneSlice(s.Signers)}
}

// --- HSYNCPARAMFlag: boolean key (presence = true, no value) ---
// Follows SVCB no-default-alpn pattern: zero-length value on the wire,
// bare key name in presentation format.

type HSYNCPARAMFlag struct {
	code HSYNCPARAMKey
}

func (s *HSYNCPARAMFlag) Key() HSYNCPARAMKey    { return s.code }
func (s *HSYNCPARAMFlag) String() string        { return "" }
func (s *HSYNCPARAMFlag) pack() ([]byte, error) { return []byte{}, nil }
func (s *HSYNCPARAMFlag) len() int              { return 0 }

func (s *HSYNCPARAMFlag) unpack(b []byte) error {
	if len(b) != 0 {
		return fmt.Errorf("dns: hsyncparam %s: flag key must have no value", s.code)
	}
	return nil
}

func (s *HSYNCPARAMFlag) parse(b string) error {
	if b != "" {
		return fmt.Errorf("dns: hsyncparam %s: flag key must have no value", s.code)
	}
	return nil
}

func (s *HSYNCPARAMFlag) copy() HSYNCPARAMKeyValue {
	return &HSYNCPARAMFlag{code: s.code}
}

// --- HSYNCPARAMLocal: catch-all for unknown keys ---

type HSYNCPARAMLocal struct {
	KeyCode HSYNCPARAMKey
	Data    []byte
}

func (s *HSYNCPARAMLocal) Key() HSYNCPARAMKey    { return s.KeyCode }
func (s *HSYNCPARAMLocal) String() string        { return hsyncparamParamToStr(s.Data) }
func (s *HSYNCPARAMLocal) pack() ([]byte, error) { return cloneSlice(s.Data), nil }
func (s *HSYNCPARAMLocal) len() int              { return len(s.Data) }

func (s *HSYNCPARAMLocal) unpack(b []byte) error {
	s.Data = cloneSlice(b)
	return nil
}

func (s *HSYNCPARAMLocal) parse(b string) error {
	data, err := hsyncparamParseParam(b)
	if err != nil {
		return fmt.Errorf("dns: hsyncparamlocal: hsyncparam private/experimental key %w", err)
	}
	s.Data = data
	return nil
}

func (s *HSYNCPARAMLocal) copy() HSYNCPARAMKeyValue {
	return &HSYNCPARAMLocal{s.KeyCode, cloneSlice(s.Data)}
}

// --- String conversion helpers for HSYNCPARAMLocal ---

func hsyncparamParamToStr(s []byte) string {
	var str strings.Builder
	str.Grow(4 * len(s))
	for _, e := range s {
		if ' ' <= e && e <= '~' {
			switch e {
			case '"', ';', ' ', '\\':
				str.WriteByte('\\')
				str.WriteByte(e)
			default:
				str.WriteByte(e)
			}
		} else {
			str.WriteString(escapeByte(e))
		}
	}
	return str.String()
}

func hsyncparamParseParam(b string) ([]byte, error) {
	data := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] != '\\' {
			data = append(data, b[i])
			i++
			continue
		}
		if i+1 == len(b) {
			return nil, errors.New("escape unterminated")
		}
		if isDigit(b[i+1]) {
			if i+3 < len(b) && isDigit(b[i+2]) && isDigit(b[i+3]) {
				a, err := strconv.ParseUint(b[i+1:i+4], 10, 8)
				if err == nil {
					i += 4
					data = append(data, byte(a))
					continue
				}
			}
			return nil, errors.New("bad escaped octet")
		} else {
			data = append(data, b[i+1])
			i += 2
		}
	}
	return data, nil
}
