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
	State  uint8 // 0=OFF, 1=ON
	NSmgmt uint8 // 1=OWNER, 2=AGENT
	Sign   uint8 // 1=YES, 2=NO
	Target string
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
	HsyncSignYES: "YES",
	HsyncSignNO:  "NO",
}

var StringToHsyncSign = map[string]uint8{
	"YES": HsyncSignYES,
	"NO":  HsyncSignNO,
}

func NewHSYNC() dns.PrivateRdata { return new(HSYNC) }

func (rd HSYNC) String() string {
	return fmt.Sprintf("%-3s  %-3s  %-3s  %s", HsyncStateToString[rd.State], HsyncNSmgmtToString[rd.NSmgmt], HsyncSignToString[rd.Sign], rd.Target)
}

func (rd *HSYNC) Parse(txt []string) error {
	log.Printf("parsing HSYNC: %v", txt)
	if len(txt) != 4 {
		return errors.New("HSYNC requires values for State, NSmgmt and Sign plus a target domain name")
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

	tgt := dns.Fqdn(txt[3])
	if _, ok := dns.IsDomainName(tgt); !ok {
		return fmt.Errorf("invalid HSYNC target: %s", txt[2])
	}

	rd.State = state
	rd.NSmgmt = nsmgmt
	rd.Sign = sign
	rd.Target = tgt

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

	off, err = dns.PackDomainName(rd.Target, buf, off, nil, false)
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

	rd.Target, off, err = dns.UnpackDomainName(buf, off)
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
	d.Target = rd.Target
	return nil
}

func (rd *HSYNC) Len() int {
	//	return 1 + 1 + 2 + len(rd.Target) + 1 // add 1 for terminating 0
	return 1 + 1 + 1 + len(rd.Target) + 1 // add 1 for terminating 0
}

func RegisterHsyncRR() error {
	dns.PrivateHandle("HSYNC", TypeHSYNC, NewHSYNC)
	log.Printf("Registered HSYNC RR")
	return nil
}
