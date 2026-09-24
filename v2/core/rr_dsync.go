/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package core

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func init() {
	RegisterDsyncRR()
}

// Zone file syntax:
//   owner TTL CLASS DSYNC rrtype scheme port target
//
// Example:
//   _dsync.example.com. 3600 IN DSYNC CDS NOTIFY 5359 ns1.example.com.
//
// Fields:
//   rrtype  - RR type this DSYNC applies to (e.g. CDS, CDNSKEY, CSYNC, DNSKEY),
//             or TYPEnnn
//   scheme  - sync scheme: NOTIFY, UPDATE, SCANNER, API, MSUPDATE, REPORT,
//             or a decimal 0-255
//   port    - TCP/UDP port number, 0-65535
//   target  - FQDN of the target server

type DSYNC struct {
	Type   uint16
	Scheme DsyncScheme
	Port   uint16
	Target string
}

type DsyncScheme uint8

const (
	SchemeNotify  = 1
	SchemeUpdate  = 2
	SchemeScanner = 3
	SchemeAPI     = 4
	// Private schemes:
	SchemeMSUpdate = 129
	SchemeReport   = 130
)

var SchemeToString = map[DsyncScheme]string{
	SchemeNotify:  "NOTIFY",
	SchemeUpdate:  "UPDATE",
	SchemeScanner: "SCANNER",
	SchemeAPI:     "API",
	// Private schemes:
	SchemeMSUpdate: "MSUPDATE", // MSUPDATE is used in a multi-signer context and indicates a DNS UPDATE sent from a signer to the upstream unsigned zone.
	SchemeReport:   "REPORT",
}

var StringToScheme = map[string]DsyncScheme{
	"NOTIFY":   SchemeNotify,
	"UPDATE":   SchemeUpdate,
	"SCANNER":  SchemeScanner,
	"API":      SchemeAPI,
	"MSUPDATE": SchemeMSUpdate,
	"REPORT":   SchemeReport,
	"REPORTER": SchemeReport, // Keep this for backwards compatibility
}

func NewDSYNC() dns.PrivateRdata { return new(DSYNC) }

// String prints the type as its mnemonic or TYPEnnn, and the scheme as its
// mnemonic or, for a scheme without one, its decimal: every value the rdata
// can hold prints as something Parse reads back.
func (rd DSYNC) String() string {
	return fmt.Sprintf("%s\t%s %d %s", dsyncTypeString(rd.Type), dsyncSchemeString(rd.Scheme), rd.Port, rd.Target)
}

// dsyncTypeString prints the RRtype field as its mnemonic when that reads back
// as the same type, and as TYPEnnn otherwise. The DNS library names type 0
// "None" and type 65535 "Reserved", and a zone file can hold neither.
func dsyncTypeString(t uint16) string {
	if name, ok := dns.TypeToString[t]; ok {
		if back, ok := dns.StringToType[strings.ToUpper(name)]; ok && back == t {
			return name
		}
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func dsyncSchemeString(s DsyncScheme) string {
	if name, ok := SchemeToString[s]; ok {
		return name
	}
	return strconv.Itoa(int(s))
}

func (rd *DSYNC) Parse(txt []string) error {
	if len(txt) != 4 {
		return errors.New("DSYNC requires a type, a scheme, a port and a target")
	}
	t, err := parseDsyncType(txt[0])
	if err != nil {
		return err
	}

	scheme, err := parseDsyncScheme(txt[1])
	if err != nil {
		return err
	}

	port, err := strconv.ParseUint(txt[2], 10, 16)
	if err != nil {
		return fmt.Errorf("invalid DSYNC port %q: not a number from 0 to 65535", txt[2])
	}

	tgt := dns.Fqdn(txt[3])
	if _, ok := dns.IsDomainName(tgt); !ok {
		return fmt.Errorf("invalid DSYNC target: %s", txt[3])
	}

	rd.Type = t
	rd.Scheme = scheme
	rd.Port = uint16(port)
	rd.Target = tgt

	return nil
}

// parseDsyncType reads the RRtype field: a mnemonic, or TYPEnnn (RFC 3597)
// for any 16-bit value. Type 0 is reserved, but it arrives by transfer like any
// other and must read back from a zone file once written to one, so it parses
// like the null scheme does.
func parseDsyncType(s string) (uint16, error) {
	u := strings.ToUpper(s)
	if t, ok := dns.StringToType[u]; ok {
		return t, nil
	}
	if num, ok := strings.CutPrefix(u, "TYPE"); ok {
		if t, err := strconv.ParseUint(num, 10, 16); err == nil {
			return uint16(t), nil
		}
	}
	return 0, fmt.Errorf("invalid DSYNC type: %s", s)
}

// parseDsyncScheme reads the scheme field: a mnemonic, or any decimal 0-255.
// The null scheme, the unassigned ones and the private-use ones all parse;
// whether a record is worth acting on is Usable's question, not the parser's.
func parseDsyncScheme(s string) (DsyncScheme, error) {
	if scheme, ok := StringToScheme[strings.ToUpper(s)]; ok {
		return scheme, nil
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid DSYNC scheme %q: not a known mnemonic or a number from 0 to 255", s)
	}
	return DsyncScheme(n), nil
}

// Usable reports whether a DSYNC record names somewhere a notification can go:
// a scheme other than the null scheme 0, a port other than 0, and a target
// other than the root. Every consumer that picks a record to act on picks
// only a usable one (#757).
func (rd *DSYNC) Usable() bool {
	return rd != nil && rd.Scheme != 0 && rd.Port != 0 && dns.Fqdn(rd.Target) != "."
}

func (rd *DSYNC) Pack(buf []byte) (int, error) {
	var off int
	off, err := packUint16(rd.Type, buf, off)
	if err != nil {
		return off, err
	}

	off, err = packUint8(uint8(rd.Scheme), buf, off)
	if err != nil {
		return off, err
	}

	off, err = packUint16(rd.Port, buf, off)
	if err != nil {
		return off, err
	}

	off, err = dns.PackDomainName(rd.Target, buf, off, nil, false)
	if err != nil {
		return off, err
	}

	return off, nil
}

// Unpack reads every field; rdata that ends before the target is an error.
// It used to return early, with no error, wherever the buffer ran out, which
// made a truncated record a DSYNC with its missing fields zero.
func (rd *DSYNC) Unpack(buf []byte) (int, error) {
	var off = 0
	var err error
	var tmp uint8

	rd.Type, off, err = unpackUint16(buf, off)
	if err != nil {
		return off, fmt.Errorf("DSYNC rdata ends before the target: %w", err)
	}

	tmp, off, err = unpackUint8(buf, off)
	if err != nil {
		return off, fmt.Errorf("DSYNC rdata ends before the target: %w", err)
	}
	rd.Scheme = DsyncScheme(tmp)

	rd.Port, off, err = unpackUint16(buf, off)
	if err != nil {
		return off, fmt.Errorf("DSYNC rdata ends before the target: %w", err)
	}

	rd.Target, off, err = dns.UnpackDomainName(buf, off)
	if err != nil {
		return off, fmt.Errorf("DSYNC target: %w", err)
	}
	return off, nil
}

func (rd *DSYNC) Copy(dest dns.PrivateRdata) error {
	cp := make([]byte, rd.Len())
	_, err := rd.Pack(cp)
	if err != nil {
		return err
	}

	d := dest.(*DSYNC)
	d.Type = rd.Type
	d.Scheme = rd.Scheme
	d.Port = rd.Port
	d.Target = rd.Target
	return nil
}

func (rd *DSYNC) Len() int {
	return 1 + 2 + 2 + len(rd.Target) + 1 // add 1 for terminating 0
}

func RegisterDsyncRR() error {
	dns.PrivateHandle("DSYNC", TypeDSYNC, NewDSYNC)
	// Explicitly set TypeToString to use "DSYNC" for printing
	dns.TypeToString[TypeDSYNC] = "DSYNC"
	return nil
}
