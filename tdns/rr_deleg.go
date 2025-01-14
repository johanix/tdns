package tdns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func init() {
	RegisterDelegRR()
}

// SVCBKey is the type of the keys used in the SVCB RR.
type DELEGKey uint16

// Keys defined in rfc9460
const (
	DELEG_MANDATORY DELEGKey = iota
	DELEG_ALPN
	DELEG_NO_DEFAULT_ALPN
	DELEG_PORT
	DELEG_IPV4HINT
	DELEG_ECHCONFIG
	DELEG_IPV6HINT
	DELEG_DOHPATH // rfc9461 Section 5
	DELEG_OHTTP   // rfc9540 Section 8

	deleg_RESERVED DELEGKey = 65535
)

var delegKeyToStringMap = map[DELEGKey]string{
	DELEG_MANDATORY:       "mandatory",
	DELEG_ALPN:            "alpn",
	DELEG_NO_DEFAULT_ALPN: "no-default-alpn",
	DELEG_PORT:            "port",
	DELEG_IPV4HINT:        "ipv4hint",
	//	DELEG_ECHCONFIG:       "ech",
	DELEG_IPV6HINT: "ipv6hint",
	// DELEG_DOHPATH:         "dohpath",
	// DELEG_OHTTP:           "ohttp",
}

var delegStringToKeyMap = reverseDELEGKeyMap(delegKeyToStringMap)

func reverseDELEGKeyMap(m map[DELEGKey]string) map[string]DELEGKey {
	n := make(map[string]DELEGKey, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}

func (key DELEGKey) String() string {
	if x := delegKeyToStringMap[key]; x != "" {
		return x
	}
	if key == deleg_RESERVED {
		return ""
	}
	return "key" + strconv.FormatUint(uint64(key), 10)
}

func delegStringToKey(s string) DELEGKey {
	if strings.HasPrefix(s, "key") {
		a, err := strconv.ParseUint(s[3:], 10, 16)
		// no leading zeros
		// key shouldn't be registered
		if err != nil || a == 65535 || s[3] == '0' || delegKeyToStringMap[DELEGKey(a)] != "" {
			return deleg_RESERVED
		}
		return DELEGKey(a)
	}
	if key, ok := delegStringToKeyMap[s]; ok {
		return key
	}
	return deleg_RESERVED
}

// johani
func (rr *DELEG) Parse(s []string) error {
	zl := newZLexer(strings.NewReader(strings.Join(s, " ")))
	pe := rr.parse(zl, "")
	if pe != nil {
		return errors.New(pe.Error())
	}
	return nil
}

func (rr *DELEG) parse(c *zlexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.token, 10, 16)
	if e != nil || l.err {
		return &ParseError{file: l.token, err: "bad DELEG priority", lex: l}
	}
	rr.Priority = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	rr.Target = l.token

	name, nameOk := toAbsoluteName(l.token, o)
	if l.err || !nameOk {
		return &ParseError{file: l.token, err: "bad DELEG Target", lex: l}
	}
	rr.Target = name

	// Values (if any)
	l, _ = c.Next()
	var xs []DELEGKeyValue
	// Helps require whitespace between pairs.
	// Prevents key1000="a"key1001=...
	canHaveNextKey := true
	for l.value != zNewline && l.value != zEOF {
		switch l.value {
		case zString:
			if !canHaveNextKey {
				// The key we can now read was probably meant to be
				// a part of the last value.
				return &ParseError{file: l.token, err: "bad DELEG value quotation", lex: l}
			}

			// In key=value pairs, value does not have to be quoted unless value
			// contains whitespace. And keys don't need to have values.
			// Similarly, keys with an equality signs after them don't need values.
			// l.token includes at least up to the first equality sign.
			idx := strings.IndexByte(l.token, '=')
			var key, value string
			if idx < 0 {
				// Key with no value and no equality sign
				key = l.token
			} else if idx == 0 {
				return &ParseError{file: l.token, err: "bad DELEG key", lex: l}
			} else {
				key, value = l.token[:idx], l.token[idx+1:]

				if value == "" {
					// We have a key and an equality sign. Maybe we have nothing
					// after "=" or we have a double quote.
					l, _ = c.Next()
					if l.value == zQuote {
						// Only needed when value ends with double quotes.
						// Any value starting with zQuote ends with it.
						canHaveNextKey = false

						l, _ = c.Next()
						switch l.value {
						case zString:
							// We have a value in double quotes.
							value = l.token
							l, _ = c.Next()
							if l.value != zQuote {
								return &ParseError{file: l.token, err: "DELEG unterminated value", lex: l}
							}
						case zQuote:
							// There's nothing in double quotes.
						default:
							return &ParseError{file: l.token, err: "bad DELEG value", lex: l}
						}
					}
				}
			}
			kv := makeDELEGKeyValue(delegStringToKey(key))
			if kv == nil {
				return &ParseError{file: l.token, err: "bad DELEG key", lex: l}
			}
			if err := kv.parse(value); err != nil {
				return &ParseError{file: l.token, wrappedErr: err, lex: l}
			}
			xs = append(xs, kv)
		case zQuote:
			return &ParseError{file: l.token, err: "DELEG key can't contain double quotes", lex: l}
		case zBlank:
			canHaveNextKey = true
		default:
			return &ParseError{file: l.token, err: "bad DELEG values", lex: l}
		}
		l, _ = c.Next()
	}

	// "In AliasMode, records SHOULD NOT include any SvcParams, and recipients MUST
	// ignore any SvcParams that are present."
	// However, we don't check rr.Priority == 0 && len(xs) > 0 here
	// It is the responsibility of the user of the library to check this.
	// This is to encourage the fixing of the source of this error.

	rr.Value = xs
	return nil
}

// makeSVCBKeyValue returns an SVCBKeyValue struct with the key or nil for reserved keys.
func makeDELEGKeyValue(key DELEGKey) DELEGKeyValue {
	switch key {
	case DELEG_MANDATORY:
		return new(DELEGMandatory)
	case DELEG_ALPN:
		return new(DELEGAlpn)
	case DELEG_NO_DEFAULT_ALPN:
		return new(DELEGNoDefaultAlpn)
	case DELEG_PORT:
		return new(DELEGPort)
	case DELEG_IPV4HINT:
		return new(DELEGIPv4Hint)
	//case DELEG_ECHCONFIG:
	//	return new(DELEGECHConfig)
	case DELEG_IPV6HINT:
		return new(DELEGIPv6Hint)
	//case DELEG_DOHPATH:
	//	return new(DELEGDoHPath)
	//case DELEG_OHTTP:
	//	return new(DELEGOhttp)
	case deleg_RESERVED:
		return nil
	default:
		e := new(DELEGLocal)
		e.KeyCode = key
		return e
	}
}

type DELEG struct {
	// Hdr      dns.RR_Header
	Priority uint16          // If zero, Value must be empty or discarded by the user of this library
	Target   string          `dns:"domain-name"`
	Value    []DELEGKeyValue `dns:"pairs"`
}

const TypeDELEG = 65287

func NewDELEG() dns.PrivateRdata { return new(DELEG) }

func (rr *DELEG) Copy(dest dns.PrivateRdata) error {
	d := dest.(*DELEG)
	d.Value = make([]DELEGKeyValue, len(rr.Value))
	for i, e := range rr.Value {
		d.Value[i] = e.copy()
	}

	d.Priority = rr.Priority
	d.Target = rr.Target
	return nil
}

// johani
func (rr *DELEG) Len() int {
	l := 2 // Priority
	l += len(rr.Target) + 1
	for _, x := range rr.Value {
		l += 4 + int(x.len())
	}
	return l
}

// johani
func (rr *DELEG) Pack(buf []byte) (int, error) {
	var off int
	var err error
	off, err = packUint16(rr.Priority, buf, off)
	if err != nil {
		return off, err
	}
	off, err = dns.PackDomainName(rr.Target, buf, off, nil, true)
	if err != nil {
		return off, err
	}
	off, err = packDelegData(rr.Value, buf, off)
	if err != nil {
		return off, err
	}
	// log.Printf("DEBUG DELEG.Pack: final off = %d, buf=%v (string: %s)", off, buf, string(buf))
	return off, nil
}

func (rr *DELEG) Unpack(buf []byte) (int, error) {
	// log.Printf("DEBUG DELEG.Unpack: buf=%v (string: %s)", buf, string(buf))
	var off int
	var err error
	rr.Priority, off, err = unpackUint16(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}
	rr.Target, off, err = dns.UnpackDomainName(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}
	rr.Value, off, err = unpackDelegData(buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

// johani
func RegisterDelegRR() error {
	dns.PrivateHandle("DELEG", TypeDELEG, NewDELEG)
	return nil
}

func packDelegData(pairs []DELEGKeyValue, msg []byte, off int) (int, error) {
	pairs = cloneSlice(pairs)
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Key() < pairs[j].Key()
	})
	prev := deleg_RESERVED
	for _, el := range pairs {
		if el.Key() == prev {
			return len(msg), errors.New("repeated DELEG keys are not allowed")
		}
		prev = el.Key()
		packed, err := el.pack()
		if err != nil {
			return len(msg), err
		}
		off, err = packUint16(uint16(el.Key()), msg, off)
		if err != nil {
			return len(msg), errors.New("overflow packing DELEG")
		}
		off, err = packUint16(uint16(len(packed)), msg, off)
		if err != nil || off+len(packed) > len(msg) {
			return len(msg), errors.New("overflow packing DELEG")
		}
		copy(msg[off:off+len(packed)], packed)
		off += len(packed)
	}
	return off, nil
}

func unpackDelegData(msg []byte, off int) ([]DELEGKeyValue, int, error) {
	var xs []DELEGKeyValue
	var code uint16
	var length uint16
	var err error
	for off < len(msg) {
		code, off, err = unpackUint16(msg, off)
		if err != nil {
			return nil, len(msg), errors.New("overflow unpacking DELEG")
		}
		length, off, err = unpackUint16(msg, off)
		if err != nil || off+int(length) > len(msg) {
			return nil, len(msg), errors.New("overflow unpacking DELEG")
		}
		e := makeDELEGKeyValue(DELEGKey(code))
		if e == nil {
			return nil, len(msg), errors.New("bad DELEG key")
		}
		if err := e.unpack(msg[off : off+int(length)]); err != nil {
			return nil, len(msg), err
		}
		if len(xs) > 0 && e.Key() <= xs[len(xs)-1].Key() {
			return nil, len(msg), errors.New("DELEG keys not in strictly increasing order")
		}
		xs = append(xs, e)
		off += int(length)
	}
	return xs, off, nil
}

// DELEGKeyValue defines a key=value pair for the DELEG RR type.
// A DELEG RR can have multiple DELEGKeyValues appended to it.
type DELEGKeyValue interface {
	Key() DELEGKey         // Key returns the numerical key code.
	pack() ([]byte, error) // pack returns the encoded value.
	unpack([]byte) error   // unpack sets the value.
	String() string        // String returns the string representation of the value.
	parse(string) error    // parse sets the value to the given string representation of the value.
	copy() DELEGKeyValue   // copy returns a deep-copy of the pair.
	len() int              // len returns the length of value in the wire format.
}

// SVCBMandatory pair adds to required keys that must be interpreted for the RR
// to be functional. If ignored, the whole RRSet must be ignored.
// "port" and "no-default-alpn" are mandatory by default if present,
// so they shouldn't be included here.
//
// It is incumbent upon the user of this library to reject the RRSet if
// or avoid constructing such an RRSet that:
// - "mandatory" is included as one of the keys of mandatory
// - no key is listed multiple times in mandatory
// - all keys listed in mandatory are present
// - escape sequences are not used in mandatory
// - mandatory, when present, lists at least one key
//
// Basic use pattern for creating a mandatory option:
//
//	s := &dns.SVCB{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}}
//	e := new(dns.SVCBMandatory)
//	e.Code = []uint16{dns.SVCB_ALPN}
//	s.Value = append(s.Value, e)
//	t := new(dns.SVCBAlpn)
//	t.Alpn = []string{"xmpp-client"}
//	s.Value = append(s.Value, t)
type DELEGMandatory struct {
	Code []DELEGKey
}

func (*DELEGMandatory) Key() DELEGKey { return DELEG_MANDATORY }

func (s *DELEGMandatory) String() string {
	str := make([]string, len(s.Code))
	for i, e := range s.Code {
		str[i] = e.String()
	}
	return strings.Join(str, ",")
}

func (s *DELEGMandatory) pack() ([]byte, error) {
	codes := cloneSlice(s.Code)
	sort.Slice(codes, func(i, j int) bool {
		return codes[i] < codes[j]
	})
	b := make([]byte, 2*len(codes))
	for i, e := range codes {
		binary.BigEndian.PutUint16(b[2*i:], uint16(e))
	}
	return b, nil
}

func (s *DELEGMandatory) unpack(b []byte) error {
	if len(b)%2 != 0 {
		return errors.New("dns: delegmandatory: value length is not a multiple of 2")
	}
	codes := make([]DELEGKey, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		// We assume strictly increasing order.
		codes = append(codes, DELEGKey(binary.BigEndian.Uint16(b[i:])))
	}
	s.Code = codes
	return nil
}

func (s *DELEGMandatory) parse(b string) error {
	codes := make([]DELEGKey, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var key string
		key, b, _ = strings.Cut(b, ",")
		codes = append(codes, delegStringToKey(key))
	}
	s.Code = codes
	return nil
}

func (s *DELEGMandatory) len() int {
	return 2 * len(s.Code)
}

func (s *DELEGMandatory) copy() DELEGKeyValue {
	return &DELEGMandatory{cloneSlice(s.Code)}
}

// SVCBAlpn pair is used to list supported connection protocols.
// The user of this library must ensure that at least one protocol is listed when alpn is present.
// Protocol IDs can be found at:
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
// Basic use pattern for creating an alpn option:
//
//	h := new(dns.HTTPS)
//	h.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
//	e := new(dns.SVCBAlpn)
//	e.Alpn = []string{"h2", "http/1.1"}
//	h.Value = append(h.Value, e)
type DELEGAlpn struct {
	Alpn []string
}

func (*DELEGAlpn) Key() DELEGKey { return DELEG_ALPN }

func (s *DELEGAlpn) String() string {
	// An ALPN value is a comma-separated list of values, each of which can be
	// an arbitrary binary value. In order to allow parsing, the comma and
	// backslash characters are themselves escaped.
	//
	// However, this escaping is done in addition to the normal escaping which
	// happens in zone files, meaning that these values must be
	// double-escaped. This looks terrible, so if you see a never-ending
	// sequence of backslash in a zone file this may be why.
	//
	// https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-08#appendix-A.1
	var str strings.Builder
	for i, alpn := range s.Alpn {
		// 4*len(alpn) is the worst case where we escape every character in the alpn as \123, plus 1 byte for the ',' separating the alpn from others
		str.Grow(4*len(alpn) + 1)
		if i > 0 {
			str.WriteByte(',')
		}
		for j := 0; j < len(alpn); j++ {
			e := alpn[j]
			if ' ' > e || e > '~' {
				str.WriteString(escapeByte(e))
				continue
			}
			switch e {
			// We escape a few characters which may confuse humans or parsers.
			case '"', ';', ' ':
				str.WriteByte('\\')
				str.WriteByte(e)
			// The comma and backslash characters themselves must be
			// doubly-escaped. We use `\\` for the first backslash and
			// the escaped numeric value for the other value. We especially
			// don't want a comma in the output.
			case ',':
				str.WriteString(`\\\044`)
			case '\\':
				str.WriteString(`\\\092`)
			default:
				str.WriteByte(e)
			}
		}
	}
	return str.String()
}

func (s *DELEGAlpn) pack() ([]byte, error) {
	// Liberally estimate the size of an alpn as 10 octets
	b := make([]byte, 0, 10*len(s.Alpn))
	for _, e := range s.Alpn {
		if e == "" {
			return nil, errors.New("dns: delegalpn: empty alpn-id")
		}
		if len(e) > 255 {
			return nil, errors.New("dns: delegalpn: alpn-id too long")
		}
		b = append(b, byte(len(e)))
		b = append(b, e...)
	}
	return b, nil
}

func (s *DELEGAlpn) unpack(b []byte) error {
	// Estimate the size of the smallest alpn as 4 bytes
	alpn := make([]string, 0, len(b)/4)
	for i := 0; i < len(b); {
		length := int(b[i])
		i++
		if i+length > len(b) {
			return errors.New("dns: delegalpn: alpn array overflowing")
		}
		alpn = append(alpn, string(b[i:i+length]))
		i += length
	}
	s.Alpn = alpn
	return nil
}

func (s *DELEGAlpn) parse(b string) error {
	if len(b) == 0 {
		s.Alpn = []string{}
		return nil
	}

	alpn := []string{}
	a := []byte{}
	for p := 0; p < len(b); {
		c, q := nextByte(b, p)
		if q == 0 {
			return errors.New("dns: delegalpn: unterminated escape")
		}
		p += q
		// If we find a comma, we have finished reading an alpn.
		if c == ',' {
			if len(a) == 0 {
				return errors.New("dns: delegalpn: empty protocol identifier")
			}
			alpn = append(alpn, string(a))
			a = []byte{}
			continue
		}
		// If it's a backslash, we need to handle a comma-separated list.
		if c == '\\' {
			dc, dq := nextByte(b, p)
			if dq == 0 {
				return errors.New("dns: delegalpn: unterminated escape decoding comma-separated list")
			}
			if dc != '\\' && dc != ',' {
				return errors.New("dns: delegalpn: bad escaped character decoding comma-separated list")
			}
			p += dq
			c = dc
		}
		a = append(a, c)
	}
	// Add the final alpn.
	if len(a) == 0 {
		return errors.New("dns: delegalpn: last protocol identifier empty")
	}
	s.Alpn = append(alpn, string(a))
	return nil
}

func (s *DELEGAlpn) len() int {
	var l int
	for _, e := range s.Alpn {
		l += 1 + len(e)
	}
	return l
}

func (s *DELEGAlpn) copy() DELEGKeyValue {
	return &DELEGAlpn{cloneSlice(s.Alpn)}
}

// SVCBNoDefaultAlpn pair signifies no support for default connection protocols.
// Should be used in conjunction with alpn.
// Basic use pattern for creating a no-default-alpn option:
//
//	s := &dns.SVCB{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}}
//	t := new(dns.SVCBAlpn)
//	t.Alpn = []string{"xmpp-client"}
//	s.Value = append(s.Value, t)
//	e := new(dns.SVCBNoDefaultAlpn)
//	s.Value = append(s.Value, e)
type DELEGNoDefaultAlpn struct{}

func (*DELEGNoDefaultAlpn) Key() DELEGKey         { return DELEG_NO_DEFAULT_ALPN }
func (*DELEGNoDefaultAlpn) copy() DELEGKeyValue   { return &DELEGNoDefaultAlpn{} }
func (*DELEGNoDefaultAlpn) pack() ([]byte, error) { return []byte{}, nil }
func (*DELEGNoDefaultAlpn) String() string        { return "" }
func (*DELEGNoDefaultAlpn) len() int              { return 0 }

func (*DELEGNoDefaultAlpn) unpack(b []byte) error {
	if len(b) != 0 {
		return errors.New("dns: svcbnodefaultalpn: no-default-alpn must have no value")
	}
	return nil
}

func (*DELEGNoDefaultAlpn) parse(b string) error {
	if b != "" {
		return errors.New("dns: delegnodefaultalpn: no-default-alpn must have no value")
	}
	return nil
}

// SVCBPort pair defines the port for connection.
// Basic use pattern for creating a port option:
//
//	s := &dns.SVCB{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}}
//	e := new(dns.SVCBPort)
//	e.Port = 80
//	s.Value = append(s.Value, e)
type DELEGPort struct {
	Port uint16
}

func (*DELEGPort) Key() DELEGKey         { return DELEG_PORT }
func (*DELEGPort) len() int              { return 2 }
func (s *DELEGPort) String() string      { return strconv.FormatUint(uint64(s.Port), 10) }
func (s *DELEGPort) copy() DELEGKeyValue { return &DELEGPort{s.Port} }

func (s *DELEGPort) unpack(b []byte) error {
	if len(b) != 2 {
		return errors.New("dns: delegport: port length is not exactly 2 octets")
	}
	s.Port = binary.BigEndian.Uint16(b)
	return nil
}

func (s *DELEGPort) pack() ([]byte, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, s.Port)
	return b, nil
}

func (s *DELEGPort) parse(b string) error {
	port, err := strconv.ParseUint(b, 10, 16)
	if err != nil {
		return errors.New("dns: delegport: port out of range")
	}
	s.Port = uint16(port)
	return nil
}

// SVCBIPv4Hint pair suggests an IPv4 address which may be used to open connections
// if A and AAAA record responses for SVCB's Target domain haven't been received.
// In that case, optionally, A and AAAA requests can be made, after which the connection
// to the hinted IP address may be terminated and a new connection may be opened.
// Basic use pattern for creating an ipv4hint option:
//
//		h := new(dns.HTTPS)
//		h.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
//		e := new(dns.SVCBIPv4Hint)
//		e.Hint = []net.IP{net.IPv4(1,1,1,1).To4()}
//
//	 Or
//
//		e.Hint = []net.IP{net.ParseIP("1.1.1.1").To4()}
//		h.Value = append(h.Value, e)
type DELEGIPv4Hint struct {
	Hint []net.IP
}

func (*DELEGIPv4Hint) Key() DELEGKey { return DELEG_IPV4HINT }
func (s *DELEGIPv4Hint) len() int    { return 4 * len(s.Hint) }

func (s *DELEGIPv4Hint) pack() ([]byte, error) {
	b := make([]byte, 0, 4*len(s.Hint))
	for _, e := range s.Hint {
		x := e.To4()
		if x == nil {
			return nil, errors.New("dns: delegipv4hint: expected ipv4, hint is ipv6")
		}
		b = append(b, x...)
	}
	return b, nil
}

func (s *DELEGIPv4Hint) unpack(b []byte) error {
	if len(b) == 0 || len(b)%4 != 0 {
		return errors.New("dns: delegipv4hint: ipv4 address byte array length is not a multiple of 4")
	}
	b = cloneSlice(b)
	x := make([]net.IP, 0, len(b)/4)
	for i := 0; i < len(b); i += 4 {
		x = append(x, net.IP(b[i:i+4]))
	}
	s.Hint = x
	return nil
}

func (s *DELEGIPv4Hint) String() string {
	str := make([]string, len(s.Hint))
	for i, e := range s.Hint {
		x := e.To4()
		if x == nil {
			return "<nil>"
		}
		str[i] = x.String()
	}
	return strings.Join(str, ",")
}

func (s *DELEGIPv4Hint) parse(b string) error {
	if b == "" {
		return errors.New("dns: delegipv4hint: empty hint")
	}
	if strings.Contains(b, ":") {
		return errors.New("dns: delegipv4hint: expected ipv4, got ipv6")
	}

	hint := make([]net.IP, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		ip := net.ParseIP(e).To4()
		if ip == nil {
			return errors.New("dns: delegipv4hint: bad ip")
		}
		hint = append(hint, ip)
	}
	s.Hint = hint
	return nil
}

func (s *DELEGIPv4Hint) copy() DELEGKeyValue {
	hint := make([]net.IP, len(s.Hint))
	for i, ip := range s.Hint {
		hint[i] = cloneSlice(ip)
	}
	return &DELEGIPv4Hint{Hint: hint}
}

// SVCBECHConfig pair contains the ECHConfig structure defined in draft-ietf-tls-esni [RFC xxxx].
// Basic use pattern for creating an ech option:
//
//	h := new(dns.HTTPS)
//	h.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
//	e := new(dns.SVCBECHConfig)
//	e.ECH = []byte{0xfe, 0x08, ...}
//	h.Value = append(h.Value, e)
// type DELEGECHConfig struct {
// 	ECH []byte // Specifically ECHConfigList including the redundant length prefix
// }

// func (*DELEGECHConfig) Key() DELEGKey     { return DELEG_ECHCONFIG }
// func (s *DELEGECHConfig) String() string { return toBase64(s.ECH) }
// func (s *DELEGECHConfig) len() int       { return len(s.ECH) }

// func (s *DELEGECHConfig) pack() ([]byte, error) {
// 	return cloneSlice(s.ECH), nil
// }

// func (s *DELEGECHConfig) copy() DELEGKeyValue {
// 	return &DELEGECHConfig{cloneSlice(s.ECH)}
// }

// func (s *DELEGECHConfig) unpack(b []byte) error {
// 	s.ECH = cloneSlice(b)
// 	return nil
// }

// func (s *SVCBECHConfig) parse(b string) error {
// 	x, err := fromBase64([]byte(b))
// 	if err != nil {
// 		return errors.New("dns: svcbech: bad base64 ech")
// 	}
// 	s.ECH = x
// 	return nil
// }

// SVCBIPv6Hint pair suggests an IPv6 address which may be used to open connections
// if A and AAAA record responses for SVCB's Target domain haven't been received.
// In that case, optionally, A and AAAA requests can be made, after which the
// connection to the hinted IP address may be terminated and a new connection may be opened.
// Basic use pattern for creating an ipv6hint option:
//
//	h := new(dns.HTTPS)
//	h.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
//	e := new(dns.SVCBIPv6Hint)
//	e.Hint = []net.IP{net.ParseIP("2001:db8::1")}
//	h.Value = append(h.Value, e)
type DELEGIPv6Hint struct {
	Hint []net.IP
}

func (*DELEGIPv6Hint) Key() DELEGKey { return DELEG_IPV6HINT }
func (s *DELEGIPv6Hint) len() int    { return 16 * len(s.Hint) }

func (s *DELEGIPv6Hint) pack() ([]byte, error) {
	b := make([]byte, 0, 16*len(s.Hint))
	for _, e := range s.Hint {
		if len(e) != net.IPv6len || e.To4() != nil {
			return nil, errors.New("dns: delegipv6hint: expected ipv6, hint is ipv4")
		}
		b = append(b, e...)
	}
	return b, nil
}

func (s *DELEGIPv6Hint) unpack(b []byte) error {
	if len(b) == 0 || len(b)%16 != 0 {
		return errors.New("dns: delegipv6hint: ipv6 address byte array length not a multiple of 16")
	}
	b = cloneSlice(b)
	x := make([]net.IP, 0, len(b)/16)
	for i := 0; i < len(b); i += 16 {
		ip := net.IP(b[i : i+16])
		if ip.To4() != nil {
			return errors.New("dns: delegipv6hint: expected ipv6, got ipv4")
		}
		x = append(x, ip)
	}
	s.Hint = x
	return nil
}

func (s *DELEGIPv6Hint) String() string {
	str := make([]string, len(s.Hint))
	for i, e := range s.Hint {
		if x := e.To4(); x != nil {
			return "<nil>"
		}
		str[i] = e.String()
	}
	return strings.Join(str, ",")
}

func (s *DELEGIPv6Hint) parse(b string) error {
	if b == "" {
		return errors.New("dns: delegipv6hint: empty hint")
	}

	hint := make([]net.IP, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		ip := net.ParseIP(e)
		if ip == nil {
			return errors.New("dns: delegipv6hint: bad ip")
		}
		if ip.To4() != nil {
			return errors.New("dns: delegipv6hint: expected ipv6, got ipv4-mapped-ipv6")
		}
		hint = append(hint, ip)
	}
	s.Hint = hint
	return nil
}

func (s *DELEGIPv6Hint) copy() DELEGKeyValue {
	hint := make([]net.IP, len(s.Hint))
	for i, ip := range s.Hint {
		hint[i] = cloneSlice(ip)
	}
	return &DELEGIPv6Hint{Hint: hint}
}

// SVCBDoHPath pair is used to indicate the URI template that the
// clients may use to construct a DNS over HTTPS URI.
//
// See RFC 9461 (https://datatracker.ietf.org/doc/html/rfc9461)
// and RFC 9462 (https://datatracker.ietf.org/doc/html/rfc9462).
//
// A basic example of using the dohpath option together with the alpn
// option to indicate support for DNS over HTTPS on a certain path:
//
//	s := new(dns.SVCB)
//	s.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}
//	e := new(dns.SVCBAlpn)
//	e.Alpn = []string{"h2", "h3"}
//	p := new(dns.SVCBDoHPath)
//	p.Template = "/dns-query{?dns}"
//	s.Value = append(s.Value, e, p)
//
// The parsing currently doesn't validate that Template is a valid
// RFC 6570 URI template.
// type SVCBDoHPath struct {
// 	Template string
// }

// func (*SVCBDoHPath) Key() SVCBKey            { return SVCB_DOHPATH }
// func (s *SVCBDoHPath) String() string        { return svcbParamToStr([]byte(s.Template)) }
// func (s *SVCBDoHPath) len() int              { return len(s.Template) }
// func (s *SVCBDoHPath) pack() ([]byte, error) { return []byte(s.Template), nil }

// func (s *SVCBDoHPath) unpack(b []byte) error {
// 	s.Template = string(b)
// 	return nil
// }

// func (s *SVCBDoHPath) parse(b string) error {
// 	template, err := svcbParseParam(b)
// 	if err != nil {
// 		return fmt.Errorf("dns: svcbdohpath: %w", err)
// 	}
// 	s.Template = string(template)
// 	return nil
// }

// func (s *SVCBDoHPath) copy() SVCBKeyValue {
// 	return &SVCBDoHPath{
// 		Template: s.Template,
// 	}
// }

// The "ohttp" SvcParamKey is used to indicate that a service described in a SVCB RR
// can be accessed as a target using an associated gateway.
// Both the presentation and wire-format values for the "ohttp" parameter MUST be empty.
//
// See RFC 9460 (https://datatracker.ietf.org/doc/html/rfc9460/)
// and RFC 9230 (https://datatracker.ietf.org/doc/html/rfc9230/)
//
// A basic example of using the dohpath option together with the alpn
// option to indicate support for DNS over HTTPS on a certain path:
//
//	s := new(dns.SVCB)
//	s.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}
//	e := new(dns.SVCBAlpn)
//	e.Alpn = []string{"h2", "h3"}
//	p := new(dns.SVCBOhttp)
// s.Value = append(s.Value, e, p)
// type SVCBOhttp struct{}

// func (*SVCBOhttp) Key() SVCBKey          { return SVCB_OHTTP }
// func (*SVCBOhttp) copy() SVCBKeyValue    { return &SVCBOhttp{} }
// func (*SVCBOhttp) pack() ([]byte, error) { return []byte{}, nil }
// func (*SVCBOhttp) String() string        { return "" }
// func (*SVCBOhttp) len() int              { return 0 }

// func (*SVCBOhttp) unpack(b []byte) error {
// 	if len(b) != 0 {
// 		return errors.New("dns: svcbotthp: svcbotthp must have no value")
// 	}
// 	return nil
// }

// func (*SVCBOhttp) parse(b string) error {
// 	if b != "" {
// 		return errors.New("dns: svcbotthp: svcbotthp must have no value")
// 	}
// 	return nil
// }

// SVCBLocal pair is intended for experimental/private use. The key is recommended
// to be in the range [SVCB_PRIVATE_LOWER, SVCB_PRIVATE_UPPER].
// Basic use pattern for creating a keyNNNNN option:
//
//	h := new(dns.HTTPS)
//	h.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
//	e := new(dns.SVCBLocal)
//	e.KeyCode = 65400
//	e.Data = []byte("abc")
//	h.Value = append(h.Value, e)
type DELEGLocal struct {
	KeyCode DELEGKey // Never 65535 or any assigned keys.
	Data    []byte   // All byte sequences are allowed.
}

func (s *DELEGLocal) Key() DELEGKey         { return s.KeyCode }
func (s *DELEGLocal) String() string        { return delegParamToStr(s.Data) }
func (s *DELEGLocal) pack() ([]byte, error) { return cloneSlice(s.Data), nil }
func (s *DELEGLocal) len() int              { return len(s.Data) }

func (s *DELEGLocal) unpack(b []byte) error {
	s.Data = cloneSlice(b)
	return nil
}

func (s *DELEGLocal) parse(b string) error {
	data, err := delegParseParam(b)
	if err != nil {
		return fmt.Errorf("dns: deleglocal: deleg private/experimental key %w", err)
	}
	s.Data = data
	return nil
}

func (s *DELEGLocal) copy() DELEGKeyValue {
	return &DELEGLocal{s.KeyCode, cloneSlice(s.Data)}
}

func (rr *DELEG) String() string {
	// s := rr.Hdr.String() +
	s := strconv.Itoa(int(rr.Priority)) + " " +
		sprintName(rr.Target)
	for _, e := range rr.Value {
		s += " " + e.Key().String() + "=\"" + e.String() + "\""
	}
	return s
}

// areSVCBPairArraysEqual checks if SVCBKeyValue arrays are equal after sorting their
// copies. arrA and arrB have equal lengths, otherwise zduplicate.go wouldn't call this function.
func areDELEGPairArraysEqual(a []DELEGKeyValue, b []DELEGKeyValue) bool {
	a = cloneSlice(a)
	b = cloneSlice(b)
	sort.Slice(a, func(i, j int) bool { return a[i].Key() < a[j].Key() })
	sort.Slice(b, func(i, j int) bool { return b[i].Key() < b[j].Key() })
	for i, e := range a {
		if e.Key() != b[i].Key() {
			return false
		}
		b1, err1 := e.pack()
		b2, err2 := b[i].pack()
		if err1 != nil || err2 != nil || !bytes.Equal(b1, b2) {
			return false
		}
	}
	return true
}

// svcbParamStr converts the value of an SVCB parameter into a DNS presentation-format string.
func delegParamToStr(s []byte) string {
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

// svcbParseParam parses a DNS presentation-format string into an SVCB parameter value.
func delegParseParam(b string) ([]byte, error) {
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
