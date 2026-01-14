/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package core

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/miekg/dns"
)

func init() {
	RegisterNotifyRR()
}

// const TypeNOTIFY = 0x0F9A

type NOTIFY struct {
	Type   uint16
	Scheme uint8
	Port   uint16
	Target string
}

func NewNOTIFY() dns.PrivateRdata { return new(NOTIFY) }

func (rd NOTIFY) String() string {
	return fmt.Sprintf("%s\t%d %d %s", dns.TypeToString[rd.Type], rd.Scheme, rd.Port, rd.Target)
}

func (rd *NOTIFY) Parse(txt []string) error {
	if len(txt) != 4 {
		return errors.New("LNOTIFY requires a type, a scheme, a port and a target")
	}
	t := dns.StringToType[txt[0]]
	if t == 0 {
		return errors.New("invalid type in NOTIFY specification")
	}

	scheme, err := strconv.Atoi(txt[1])
	if err != nil {
		return fmt.Errorf("invalid NOTIFY scheme: %s. Error: %v", txt[1], err)
	}

	port, err := strconv.Atoi(txt[2])
	if err != nil {
		return fmt.Errorf("invalid NOTIFY port: %s. Error: %v", txt[2], err)
	}

	tgt := dns.Fqdn(txt[3])
	if _, ok := dns.IsDomainName(tgt); !ok {
		return fmt.Errorf("invalid NOTIFY target: %s. Error: %v", txt[3], err)
	}

	rd.Type = t
	rd.Scheme = uint8(scheme)
	rd.Port = uint16(port)
	rd.Target = tgt

	return nil
}

func (rd *NOTIFY) Pack(buf []byte) (int, error) {
	var off int
	off, err := packUint16(rd.Type, buf, off)
	if err != nil {
		return off, err
	}

	off, err = packUint8(rd.Scheme, buf, off)
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

func (rd *NOTIFY) Unpack(buf []byte) (int, error) {
	var off = 0
	var err error

	rd.Type, off, err = unpackUint16(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	rd.Scheme, off, err = unpackUint8(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	rd.Port, off, err = unpackUint16(buf, off)
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

func (rd *NOTIFY) Copy(dest dns.PrivateRdata) error {
	cp := make([]byte, rd.Len())
	_, err := rd.Pack(cp)
	if err != nil {
		return err
	}

	d := dest.(*NOTIFY)
	d.Type = rd.Type
	d.Scheme = rd.Scheme
	d.Port = rd.Port
	d.Target = rd.Target
	return nil
}

func (rd *NOTIFY) Len() int {
	return 1 + 2 + 2 + len(rd.Target) + 1 // add 1 for terminating 0
}

func RegisterNotifyRR() error {
	dns.PrivateHandle("NOTIFY", TypeNOTIFY, NewNOTIFY)
	return nil
}
