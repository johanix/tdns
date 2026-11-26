/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package imr

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func (imr *Imr) ParentZone(z string) (string, error) {
	labels := strings.Split(z, ".")
	var parent string

	if len(labels) == 1 {
		return z, nil
	} else if len(labels) > 1 {
		upone := dns.Fqdn(strings.Join(labels[1:], "."))

		// Query for SOA at the potential parent zone name using Query
		ctx := context.Background()
		resp, err := imr.imrQuery(ctx, upone, dns.TypeSOA, dns.ClassINET, false)
		if err != nil {
			return "", err
		}

		// If we got an answer with SOA in Answer section, use that zone name
		if resp.RRset != nil && len(resp.RRset.RRs) > 0 {
			// Check if this is actually a SOA record
			for _, rr := range resp.RRset.RRs {
				if soa, ok := rr.(*dns.SOA); ok {
					parent = soa.Header().Name
					return parent, nil
				}
			}
			// If we got an answer but no SOA, the response is broken
			imr.lgImr().Error("received answer for SOA query but no SOA record found", "zone", upone)
			return "", fmt.Errorf("received answer for '%s' SOA query but no SOA record found", upone)
		}

		// If Answer is empty, this is a negative response
		// Check the cache for negative response data - extract SOA from NegAuthority
		// When a negative response is cached, the SOA RRset is stored in NegAuthority,
		// and the SOA owner name is the authoritative zone (the parent)
		if imr.Cache == nil {
			return "", fmt.Errorf("imr.Cache is nil")
		}
		cached := imr.Cache.Get(upone, dns.TypeSOA)
		if cached != nil && len(cached.NegAuthority) > 0 {
			// Look for SOA RRset in NegAuthority
			for _, negRRset := range cached.NegAuthority {
				if negRRset != nil && negRRset.RRtype == dns.TypeSOA && len(negRRset.RRs) > 0 {
					// Found SOA in negative authority
					for _, rr := range negRRset.RRs {
						if soa, ok := rr.(*dns.SOA); ok {
							parent = soa.Header().Name
							return parent, nil
						}
					}
					// Use the RRset name if SOA type assertion fails
					if negRRset.Name != "" {
						parent = negRRset.Name
						return parent, nil
					}
				}
			}
		}

		imr.lgImr().Error("failed to locate parent via Answer and Authority, guessing", "zone", z)
		return upone, fmt.Errorf("failed to locate parent of '%s' via Answer and Authority", z)
	}
	imr.lgImr().Error("had difficulties splitting zone", "zone", z)
	return z, fmt.Errorf("failed to split zone name '%s' into labels", z)
}
