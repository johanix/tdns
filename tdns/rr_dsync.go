/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/miekg/dns"
)

func init() {
	RegisterDsyncRR()
}

const TypeDSYNC = 0x0F9B

type DSYNC struct {
	Type   uint16
	Scheme DsyncScheme
	Port   uint16
	Target string
}

type DsyncScheme uint8

const (
	SchemeNotify = 1
	SchemeUpdate = 2
	SchemeAPI    = 3
)

var SchemeToString = map[DsyncScheme]string{
	SchemeNotify: "NOTIFY",
	SchemeUpdate: "UPDATE",
	SchemeAPI:    "API",
}

var StringToScheme = map[string]DsyncScheme{
	"NOTIFY": SchemeNotify,
	"UPDATE": SchemeUpdate,
	"API":    SchemeAPI,
	"1":      SchemeNotify,
	"2":      SchemeUpdate,
	"3":      SchemeAPI,
}

func NewDSYNC() dns.PrivateRdata { return new(DSYNC) }

func (rd DSYNC) String() string {
	return fmt.Sprintf("%s\t%s %d %s", dns.TypeToString[rd.Type], SchemeToString[rd.Scheme], rd.Port, rd.Target)
}

func (rd *DSYNC) Parse(txt []string) error {
	if len(txt) != 4 {
		return errors.New("DSYNC requires a type, a scheme, a port and a target")
	}
	t := dns.StringToType[txt[0]]
	if t == 0 {
		return fmt.Errorf("invalid DSYNC type: %s.", txt[0])
	}

	scheme, exist := StringToScheme[txt[1]]
	if !exist {
		return fmt.Errorf("invalid DSYNC scheme: %s.", txt[1])
	}

	port, err := strconv.Atoi(txt[2])
	if err != nil {
		return fmt.Errorf("invalid DSYNC port: %s. Error: %v", txt[2], err)
	}

	tgt := dns.Fqdn(txt[3])
	if _, ok := dns.IsDomainName(tgt); !ok {
		return fmt.Errorf("invalid DSYNC target: %s.", txt[3])
	}

	rd.Type = t
	rd.Scheme = DsyncScheme(scheme)
	rd.Port = uint16(port)
	rd.Target = tgt

	return nil
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

func (rd *DSYNC) Unpack(buf []byte) (int, error) {
	var off = 0
	var err error
	var tmp uint8

	rd.Type, off, err = unpackUint16(buf, off)
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
	rd.Scheme = DsyncScheme(tmp)
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
	return nil
}
