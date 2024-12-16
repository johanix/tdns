/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Example:
// target: ms1.music.axfr.net
// baseurl: https://{TARGET}/api/v1
// port: 443
func (zd *ZoneData) PublishUriRR(target, baseurl string, port uint16) error {
	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("PublishUriRR: KeyDB.UpdateQ is nil")
	}
	if _, ok := dns.IsDomainName(target); !ok {
		return fmt.Errorf("target must be a valid domain name")
	}

	if !strings.Contains(baseurl, "{TARGET}") {
		return fmt.Errorf("baseurl must contain {TARGET} to be used as a template")
	}
	if !strings.Contains(baseurl, "{PORT}") {
		return fmt.Errorf("baseurl must contain {PORT} to be used as a template")
	}

	apiurl := strings.Replace(baseurl, "{TARGET}", target, 1)
	apiurl = strings.Replace(apiurl, "{PORT}", fmt.Sprintf("%d", port), 1)

	var uri = dns.URI{
		Priority: 1,
		Weight:   1,
		Target:   apiurl,
	}

	uri.Hdr = dns.RR_Header{
		Name:   target,
		Rrtype: dns.TypeURI,
		Class:  dns.ClassINET,
		Ttl:    7200,
	}

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{&uri},
		InternalUpdate: true,
	}

	return nil
}

func (zd *ZoneData) UnpublishUriRR(target string) error {
	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("UnpublishUriRR: KeyDB.UpdateQ is nil")
	}
	var uri = dns.URI{
		Priority: 0,
		Weight:   0,
		Target:   "",
	}

	uri.Hdr = dns.RR_Header{
		Name:   target,
		Rrtype: dns.TypeURI,
		Class:  dns.ClassANY, // Delete URI RRset
		Ttl:    0,
	}

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{&uri},
		InternalUpdate: true,
	}

	return nil
}
