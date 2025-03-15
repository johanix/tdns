/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Example:
// target: ms1.music.axfr.net
// baseurl: https://{TARGET}/api/v1
// port: 443
func (zd *ZoneData) PublishUriRR(owner, target, baseurl string, port uint16) error {
	if Globals.Debug {
		log.Printf("PublishUriRR: received request to publish URI record for %q, baseurl: %q, port: %d", target, baseurl, port)
	}
	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("PublishUriRR: KeyDB.UpdateQ is nil")
	}
	if _, ok := dns.IsDomainName(target); !ok {
		return fmt.Errorf("target must be a valid domain name")
	}

	if !strings.HasSuffix(owner, zd.ZoneName) {
		return fmt.Errorf("owner must be a subdomain of the zone name")
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
		Name:   owner,
		Rrtype: dns.TypeURI,
		Class:  dns.ClassINET,
		Ttl:    7200,
	}

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{&uri},
		InternalUpdate: true,
	}:
		// Successfully sent to channel
	case <-time.After(5 * time.Second):
		return fmt.Errorf("PublishUriRR: timeout sending update request to KeyDB.UpdateQ")
	}

	return nil
}

func (zd *ZoneData) UnpublishUriRR(owner, target string) error {
	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("UnpublishUriRR: KeyDB.UpdateQ is nil")
	}
	if _, ok := dns.IsDomainName(target); !ok {
		return fmt.Errorf("target must be a valid domain name")
	}
	if !strings.HasSuffix(owner, zd.ZoneName) {
		return fmt.Errorf("owner must be a subdomain of the zone name")
	}

	var uri = dns.URI{
		Priority: 0,
		Weight:   0,
		Target:   "",
	}

	uri.Hdr = dns.RR_Header{
		Name:   owner,
		Rrtype: dns.TypeURI,
		Class:  dns.ClassANY, // Delete URI RRset
		Ttl:    0,
	}

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{&uri},
		InternalUpdate: true,
	}:
		// Successfully sent to channel
	case <-time.After(5 * time.Second):
		return fmt.Errorf("UnpublishUriRR: timeout sending update request to KeyDB.UpdateQ")
	}

	return nil
}
