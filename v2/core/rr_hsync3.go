/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package core

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// Zone file syntax:
//   owner TTL CLASS HSYNC3 state label identity upstream
//
// Examples:
//   customer.zone. 3600 IN HSYNC3 ON cloudflare agent.cloudflare.com. netnod
//   customer.zone. 3600 IN HSYNC3 ON netnod    agent.netnod.se.      .
//
// Fields:
//   state    - ON or OFF
//   label    - the provider's Label (e.g. "netnod"): 1 to 16 characters, each
//              a lowercase ASCII letter, a digit or a hyphen. NOT an FQDN, and
//              no trailing dot.
//   identity - FQDN for agent discovery (e.g. "agent.netnod.se.")
//   upstream - the upstream provider's Label, or "." if none
//
// Label and upstream follow the Label rule that HSYNCPARAM's servers, signers
// and auditors follow (isValidHsyncLabel), so that a Label in HSYNCPARAM
// matches its HSYNC3 record octet by octet. Anything else is refused by Parse,
// Unpack and Pack.

func init() {
	RegisterHsync3RR()
}

type HSYNC3 struct {
	State    uint8  // 0=OFF, 1=ON
	Label    string // the provider's Label, e.g. "netnod" — NOT an FQDN
	Identity string // FQDN for agent discovery, e.g. "agent.netnod.se."
	Upstream string // the upstream provider's Label, or "." — NOT an FQDN
}

func NewHSYNC3() dns.PrivateRdata { return new(HSYNC3) }

func (rd HSYNC3) String() string {
	return fmt.Sprintf("%-3s  %s  %s  %s", HsyncStateToString[rd.State], rd.Label, rd.Identity, rd.Upstream)
}

func (rd *HSYNC3) Parse(txt []string) error {
	if len(txt) != 4 {
		return errors.New("HSYNC3 requires values for State, Label, Identity and Upstream")
	}

	state, exist := StringToHsyncState[txt[0]]
	if !exist {
		return fmt.Errorf("invalid HSYNC3 state: %s", txt[0])
	}

	label := txt[1]
	if err := checkHsync3Label(label); err != nil {
		return err
	}

	identity := dns.Fqdn(txt[2])
	if _, ok := dns.IsDomainName(identity); !ok {
		return fmt.Errorf("invalid HSYNC3 identity: %s", txt[2])
	}

	upstream := txt[3]
	if err := checkHsync3Upstream(upstream); err != nil {
		return err
	}

	rd.State = state
	rd.Label = label
	rd.Identity = identity
	rd.Upstream = upstream
	return nil
}

// checkHsync3Label refuses a label that is not a Label. Earlier code stored
// the label with a trailing dot ("netnod."); that is not a Label either.
func checkHsync3Label(label string) error {
	if !isValidHsyncLabel(label) {
		return fmt.Errorf("invalid HSYNC3 label %q: a Label is 1-16 of a-z, 0-9, -", label)
	}
	return nil
}

// checkHsync3Upstream accepts "." (no upstream) or a Label.
func checkHsync3Upstream(upstream string) error {
	if upstream != "." && !isValidHsyncLabel(upstream) {
		return fmt.Errorf("invalid HSYNC3 upstream %q: a Label (1-16 of a-z, 0-9, -) or \".\"", upstream)
	}
	return nil
}

// packCharacterString packs a string in DNS character-string format:
// 1 byte length prefix followed by the string bytes.
func packCharacterString(s string, buf []byte, off int) (int, error) {
	l := len(s)
	if l > 255 {
		return off, errors.New("character-string too long")
	}
	if off+1+l > len(buf) {
		return off, errors.New("overflow packing character-string")
	}
	buf[off] = byte(l)
	off++
	copy(buf[off:], s)
	off += l
	return off, nil
}

// unpackCharacterString unpacks a DNS character-string:
// reads 1 byte length prefix then that many bytes of data.
func unpackCharacterString(buf []byte, off int) (string, int, error) {
	if off >= len(buf) {
		return "", off, errors.New("overflow unpacking character-string length")
	}
	l := int(buf[off])
	off++
	if off+l > len(buf) {
		return "", off, errors.New("overflow unpacking character-string data")
	}
	s := string(buf[off : off+l])
	off += l
	return s, off, nil
}

func (rd *HSYNC3) Pack(buf []byte) (int, error) {
	if err := checkHsync3Label(rd.Label); err != nil {
		return 0, err
	}
	if err := checkHsync3Upstream(rd.Upstream); err != nil {
		return 0, err
	}
	var off int
	off, err := packUint8(rd.State, buf, off)
	if err != nil {
		return off, err
	}

	off, err = packCharacterString(rd.Label, buf, off)
	if err != nil {
		return off, err
	}

	off, err = dns.PackDomainName(rd.Identity, buf, off, nil, false)
	if err != nil {
		return off, err
	}

	off, err = packCharacterString(rd.Upstream, buf, off)
	if err != nil {
		return off, err
	}

	return off, nil
}

func (rd *HSYNC3) Unpack(buf []byte) (int, error) {
	var off = 0
	var err error

	rd.State, off, err = unpackUint8(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	rd.Label, off, err = unpackCharacterString(buf, off)
	if err != nil {
		return off, err
	}
	if err := checkHsync3Label(rd.Label); err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	rd.Identity, off, err = dns.UnpackDomainName(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	rd.Upstream, off, err = unpackCharacterString(buf, off)
	if err != nil {
		return off, err
	}
	if err := checkHsync3Upstream(rd.Upstream); err != nil {
		return off, err
	}

	return off, nil
}

func (rd *HSYNC3) Copy(dest dns.PrivateRdata) error {
	cp := make([]byte, rd.Len())
	_, err := rd.Pack(cp)
	if err != nil {
		return err
	}

	d := dest.(*HSYNC3)
	d.State = rd.State
	d.Label = rd.Label
	d.Identity = rd.Identity
	d.Upstream = rd.Upstream
	return nil
}

func (rd *HSYNC3) Len() int {
	// 1 (State) + 1+len(Label) (character-string) + len(Identity)+1 (domain-name with terminating zero) + 1+len(Upstream) (character-string)
	return 1 + 1 + len(rd.Label) + len(rd.Identity) + 1 + 1 + len(rd.Upstream)
}

func RegisterHsync3RR() error {
	dns.PrivateHandle("HSYNC3", TypeHSYNC3, NewHSYNC3)
	dns.TypeToString[TypeHSYNC3] = "HSYNC3"
	return nil
}
