/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// example.com. IN MSIGNER ON API multisigner.provider.com.
// example.com. IN MSIGNER OFF 53 ms-conductor.signerco.net.

func init() {
	RegisterMsignerRR()
}

const TypeMSIGNER = 0x0F9C

type MSIGNER struct {
	State     uint8            // 0=OFF, 1=ON
	Mechanism MsignerMechanism // 1=DNS, 2=API
	//	Port   uint16
	Target string
}

type MsignerMechanism uint8

const (
	MSignMechanismDNS = 1
	MSignMechanismAPI = 2
	MSignStateON      = 1
	MSignStateOFF     = 0
)

var StateToString = map[uint8]string{
	MSignStateON:  "ON",
	MSignStateOFF: "OFF",
}

var StringToState = map[string]uint8{
	"ON":  MSignStateON,
	"OFF": MSignStateOFF,
}

var MsignerMechanismToString = map[MsignerMechanism]string{
	MSignMechanismDNS: "DNS",
	MSignMechanismAPI: "API",
}

var StringToMsignerMechanism = map[string]MsignerMechanism{
	"DNS": MSignMechanismDNS,
	"API": MSignMechanismAPI,
}

func NewMSIGNER() dns.PrivateRdata { return new(MSIGNER) }

func (rd MSIGNER) String() string {
	//	return fmt.Sprintf("%s\t%s %d %s", StateToString[rd.State], MsignerSchemeToString[rd.Scheme], rd.Port, rd.Target)
	return fmt.Sprintf("%s\t%s %s", StateToString[rd.State], MsignerMechanismToString[rd.Mechanism], rd.Target)
}

func (rd *MSIGNER) Parse(txt []string) error {
	//	if len(txt) != 4 {
	//		return errors.New("MSIGNER requires a state, a scheme, a port and a target")
	if len(txt) != 3 {
		return errors.New("MSIGNER requires a state, a sync mechanism and a target")
	}
	state, exist := StringToState[txt[0]]
	if !exist {
		return fmt.Errorf("invalid MSIGNER type: %s.", txt[0])
	}

	mechanism, exist := StringToMsignerMechanism[txt[1]]
	if !exist {
		return fmt.Errorf("invalid MSIGNER sync mechanism: %s.", txt[1])
	}

	//	port, err := strconv.Atoi(txt[2])
	//	if err != nil {
	//		return fmt.Errorf("invalid MSIGNER port: %s. Error: %v", txt[2], err)
	//	}

	tgt := dns.Fqdn(txt[2])
	if _, ok := dns.IsDomainName(tgt); !ok {
		return fmt.Errorf("invalid MSIGNER target: %s.", txt[2])
	}

	rd.State = state
	rd.Mechanism = mechanism
	//	rd.Port = uint16(port)
	rd.Target = tgt

	return nil
}

func (rd *MSIGNER) Pack(buf []byte) (int, error) {
	var off int
	off, err := packUint8(rd.State, buf, off)
	if err != nil {
		return off, err
	}

	off, err = packUint8(uint8(rd.Mechanism), buf, off)
	if err != nil {
		return off, err
	}

	//	off, err = packUint16(rd.Port, buf, off)
	//	if err != nil {
	//		return off, err
	//	}

	off, err = dns.PackDomainName(rd.Target, buf, off, nil, false)
	if err != nil {
		return off, err
	}

	return off, nil
}

func (rd *MSIGNER) Unpack(buf []byte) (int, error) {
	var off = 0
	var err error
	var tmp uint8

	rd.State, off, err = unpackUint8(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	tmp, off, err = unpackUint8(buf, off)
	if err != nil {
		return off, err
	}
	rd.Mechanism = MsignerMechanism(tmp)
	if off == len(buf) {
		return off, nil
	}

	//	rd.Port, off, err = unpackUint16(buf, off)
	//	if err != nil {
	//		return off, err
	//	}
	//	if off == len(buf) {
	//		return off, nil
	//	}

	rd.Target, off, err = dns.UnpackDomainName(buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rd *MSIGNER) Copy(dest dns.PrivateRdata) error {
	cp := make([]byte, rd.Len())
	_, err := rd.Pack(cp)
	if err != nil {
		return err
	}

	d := dest.(*MSIGNER)
	d.State = rd.State
	d.Mechanism = rd.Mechanism
	//	d.Port = rd.Port
	d.Target = rd.Target
	return nil
}

func (rd *MSIGNER) Len() int {
	//	return 1 + 1 + 2 + len(rd.Target) + 1 // add 1 for terminating 0
	return 1 + 1 + len(rd.Target) + 1 // add 1 for terminating 0
}

func RegisterMsignerRR() error {
	dns.PrivateHandle("MSIGNER", TypeMSIGNER, NewMSIGNER)
	return nil
}
