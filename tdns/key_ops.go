/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"

	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishKeyRR(keyrr *dns.KEY) error {
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("Zone %s does not allow updates. KEY RR publication not possible", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	//	var keyrr = dns.KEY{
	//	}

	rrset := RRset{
		Name:   zd.ZoneName,
		RRs:    []dns.RR{keyrr},
		RRSIGs: []dns.RR{},
	}

	zd.mu.Lock()
	apex.RRtypes[dns.TypeKEY] = rrset
	zd.mu.Unlock()

	zd.BumpSerial()

	return nil
}
