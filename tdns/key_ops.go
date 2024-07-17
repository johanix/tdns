/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"

	"github.com/miekg/dns"
)

func (zd *ZoneData) xxxPublishKeyRR(keyrr *dns.KEY) error {
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("Zone %s does not allow updates. KEY RR publication not possible", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	rrset := RRset{
		Name:   zd.ZoneName,
		RRs:    []dns.RR{keyrr},
		RRSIGs: []dns.RR{},
	}

	zd.mu.Lock()
	apex.RRtypes[dns.TypeKEY] = rrset
	zd.Options["dirty"] = true
	zd.mu.Unlock()
	zd.BumpSerial()

	return nil
}

func (zd *ZoneData) PublishKeyRRs(sak *Sig0ActiveKeys) error {
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("Zone %s does not allow updates. KEY RR publication not possible", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	zd.mu.Lock()
	for _, pkc := range sak.Keys {
		rrset := RRset{
			Name:   zd.ZoneName,
			RRs:    []dns.RR{&pkc.KeyRR},
			RRSIGs: []dns.RR{},
		}
		apex.RRtypes[dns.TypeKEY] = rrset
	}
	zd.Options["dirty"] = true
	zd.mu.Unlock()
	zd.BumpSerial()

	return nil
}
