/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"errors"
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// example.com. IN MSIGNER ON API multisigner.provider.com.
// example.com. IN MSIGNER OFF 53 ms-conductor.signerco.net.

func init() {
	RegisterHsyncRR()
}

const TypeHSYNC = 0x0F9D

type HSYNC struct {
	State    uint8 // 0=OFF, 1=ON
	NSmgmt   uint8 // 1=OWNER, 2=AGENT
	Sign     uint8 // 1=SIGN, 2=NOSIGN
	Identity string
	Upstream string
}

const (
	HsyncStateON     uint8 = 1
	HsyncStateOFF    uint8 = 0
	HsyncNSmgmtOWNER uint8 = 1
	HsyncNSmgmtAGENT uint8 = 2
	HsyncSignYES     uint8 = 1
	HsyncSignNO      uint8 = 0
)

var HsyncStateToString = map[uint8]string{
	HsyncStateON:  "ON",
	HsyncStateOFF: "OFF",
}

var StringToHsyncState = map[string]uint8{
	"ON":  HsyncStateON,
	"OFF": HsyncStateOFF,
}

var HsyncNSmgmtToString = map[uint8]string{
	HsyncNSmgmtOWNER: "OWNER",
	HsyncNSmgmtAGENT: "AGENT",
}

var StringToHsyncNSmgmt = map[string]uint8{
	"OWNER": HsyncNSmgmtOWNER,
	"AGENT": HsyncNSmgmtAGENT,
}

var HsyncSignToString = map[uint8]string{
	HsyncSignYES: "SIGN",
	HsyncSignNO:  "NOSIGN",
}

var StringToHsyncSign = map[string]uint8{
	"SIGN":   HsyncSignYES,
	"NOSIGN": HsyncSignNO,
}

func NewHSYNC() dns.PrivateRdata { return new(HSYNC) }

func (rd HSYNC) String() string {
	return fmt.Sprintf("%-3s  %-3s  %-3s  %s %s", HsyncStateToString[rd.State], HsyncNSmgmtToString[rd.NSmgmt], HsyncSignToString[rd.Sign], rd.Identity, rd.Upstream)
}

func (rd *HSYNC) Parse(txt []string) error {
	log.Printf("parsing HSYNC: %v", txt)
	if len(txt) != 5 {
		return errors.New("HSYNC requires values for State, NSmgmt and Sign plus identity and upstream domain names")
	}
	state, exist := StringToHsyncState[txt[0]]
	if !exist {
		return fmt.Errorf("invalid HSYNC type: %s", txt[0])
	}

	nsmgmt, exist := StringToHsyncNSmgmt[txt[1]]
	if !exist {
		return fmt.Errorf("invalid HSYNC NSmgmt value: %s", txt[1])
	}

	sign, exist := StringToHsyncSign[txt[2]]
	if !exist {
		return fmt.Errorf("invalid HSYNC Sign value: %s", txt[2])
	}

	id := dns.Fqdn(txt[3])
	if _, ok := dns.IsDomainName(id); !ok {
		return fmt.Errorf("invalid HSYNC identity: %s", txt[3])
	}

	upstream := dns.Fqdn(txt[4])
	if _, ok := dns.IsDomainName(upstream); !ok {
		return fmt.Errorf("invalid HSYNC upstream: %s", txt[4])
	}

	rd.State = state
	rd.NSmgmt = nsmgmt
	rd.Sign = sign
	rd.Identity = id
	rd.Upstream = upstream
	return nil
}

func (rd *HSYNC) Pack(buf []byte) (int, error) {
	var off int
	off, err := packUint8(rd.State, buf, off)
	if err != nil {
		return off, err
	}

	off, err = packUint8(uint8(rd.NSmgmt), buf, off)
	if err != nil {
		return off, err
	}

	off, err = packUint8(uint8(rd.Sign), buf, off)
	if err != nil {
		return off, err
	}

	off, err = dns.PackDomainName(rd.Identity, buf, off, nil, false)
	if err != nil {
		return off, err
	}

	off, err = dns.PackDomainName(rd.Upstream, buf, off, nil, false)
	if err != nil {
		return off, err
	}

	return off, nil
}

func (rd *HSYNC) Unpack(buf []byte) (int, error) {
	var off = 0
	var err error

	rd.State, off, err = unpackUint8(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	rd.NSmgmt, off, err = unpackUint8(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	rd.Sign, off, err = unpackUint8(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	rd.Identity, off, err = dns.UnpackDomainName(buf, off)
	if err != nil {
		return off, err
	}

	rd.Upstream, off, err = dns.UnpackDomainName(buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rd *HSYNC) Copy(dest dns.PrivateRdata) error {
	cp := make([]byte, rd.Len())
	_, err := rd.Pack(cp)
	if err != nil {
		return err
	}

	d := dest.(*HSYNC)
	d.State = rd.State
	d.NSmgmt = rd.NSmgmt
	d.Sign = rd.Sign
	d.Identity = rd.Identity
	d.Upstream = rd.Upstream
	return nil
}

func (rd *HSYNC) Len() int {
	return 1 + 1 + 1 + len(rd.Identity) + len(rd.Upstream) + 2 // +2 for two terminating zeros
}

func RegisterHsyncRR() error {
	dns.PrivateHandle("HSYNC", TypeHSYNC, NewHSYNC)
	// log.Printf("Registered HSYNC RR")
	return nil
}
