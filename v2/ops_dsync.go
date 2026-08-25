/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// publishedDsyncRRs returns a COPY of the DSYNC records already published at an
// owner, and is the only thing that should read them.
//
// Copy, not alias. The published RRset's backing array usually has spare
// capacity -- a zone-file load sizes slices generously -- so appending onto it
// writes a synthesized DSYNC record straight into the live RRset, visible to
// queries, with no serial bump and no journal entry. That failure is invisible
// until a zone happens to have the capacity.
//
// An owner can also exist without a DSYNC RRset -- _dsync.<zone> may carry a
// TXT and nothing else -- and an owner with no RRtypes at all is a dereference
// away from taking the process down. Neither is a reason to fail publication:
// both mean "nothing published yet", which is the case the caller exists to fix.
//
// Extracted so the tests exercise this rather than restating it. They used to
// re-implement the guard inline, which meant they would have gone on passing if
// the production path regressed to an unsafe dereference.
func publishedDsyncRRs(owner *OwnerData) []dns.RR {
	if owner == nil || owner.RRtypes == nil {
		return nil
	}
	existing, ok := owner.RRtypes.Get(core.TypeDSYNC)
	if !ok {
		return nil
	}
	return append(make([]dns.RR, 0, len(existing.RRs)), existing.RRs...)
}

// publishedDsyncSchemes reports which DSYNC schemes an existing RRset already
// carries, so PublishDsyncRRs can leave those alone and synthesize only the
// rest. Anything that is not a DSYNC record is ignored rather than treated as
// an error: the caller's job is to add what is missing, not to police what the
// operator put there.
func publishedDsyncSchemes(rrs []dns.RR) map[core.DsyncScheme]bool {
	out := map[core.DsyncScheme]bool{}
	for _, rr := range rrs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		if d, ok := prr.Data.(*core.DSYNC); ok {
			out[d.Scheme] = true
		}
	}
	return out
}

func (zd *ZoneData) PublishDsyncRRs() error {
	lg.Debug("PublishDsyncRRs", "zone", zd.ZoneName)
	rrset := core.RRset{
		Name: zd.ZoneName,
	}

	// An existing DSYNC record is the operator's and is never rewritten -- but
	// the guard is PER SCHEME, not all-or-nothing.
	//
	// All-or-nothing meant that adding a scheme to a zone which already
	// published DSYNC records did nothing whatsoever, silently: no record, no
	// error, no warning. The documented remedy was to unpublish the RRset and
	// republish it, which also threw away the operator's own records and, until
	// recently, could not run at all because the delete it built did not parse.
	//
	// So: whatever is already published stays exactly as it is, and only
	// schemes with no DSYNC record of their own are synthesized.
	owner, err := zd.GetOwner("_dsync." + zd.ZoneName)
	if err != nil {
		return fmt.Errorf("PublishDsyncRRs: error fetching _dsync owner for zone %s: %v", zd.ZoneName, err)
	}
	if owner != nil {
		// Copy, do not alias. The published RRset's backing array usually has
		// spare capacity -- zone-file load sizes slices generously -- so an
		// append onto it below would write a synthesized DSYNC record straight
		// into the live RRset, visible to queries, with no serial bump and no
		// journal entry. The bug is invisible until a zone happens to have the
		// capacity, which makes it exactly the kind that survives testing.
		rrset.RRs = publishedDsyncRRs(owner)
	}
	publishedSchemes := publishedDsyncSchemes(rrset.RRs)
	alreadyPublished := len(rrset.RRs)

	ttl := 7200
	addr_rrs := []dns.RR{}
	dsync_added := false

	MaybeAddAddressRR := func(target, addr string) error {
		var addrstr string
		var addr_rr dns.RR
		var err error
		if strings.Contains(addr, ":") {
			addrstr = fmt.Sprintf("%s %d IN AAAA %s", target, ttl, addr)
			addr_rr, err = dns.NewRR(addrstr)
		} else {
			addrstr = fmt.Sprintf("%s %d IN A %s", target, ttl, addr)
			addr_rr, err = dns.NewRR(addrstr)
		}
		if err != nil {
			lg.Error("failed to create address RR", "rr", addrstr, "err", err)
			return err
		}
		for _, existing_rr := range addr_rrs {
			if dns.IsDuplicate(existing_rr, addr_rr) {
				return nil // Duplicate found, do not add
			}
		}
		addr_rrs = append(addr_rrs, addr_rr)
		return nil
	}

	dsc := DelegationSyncConfig().Parent
	lg.Debug("defined DSYNC schemes", "zone", zd.ZoneName, "schemes", dsc.Schemes)

	for _, scheme := range dsc.Schemes {
		lg.Debug("checking DSYNC scheme", "zone", zd.ZoneName, "scheme", scheme)
		if sv, known := core.StringToScheme[strings.ToUpper(scheme)]; known && publishedSchemes[sv] {
			lg.Debug("DSYNC scheme already published, leaving it alone",
				"zone", zd.ZoneName, "scheme", scheme)
			continue
		}
		switch s := strings.ToUpper(scheme); s {
		case "NOTIFY":
			replacer := zd.ZoneName
			if replacer == "." {
				replacer = "root"
			}
			target := dns.Fqdn(strings.Replace(dsc.Notify.Target, "{ZONENAME}", replacer, 1))
			if _, ok := dns.IsDomainName(target); !ok {
				return fmt.Errorf("zone %s: invalid DSYNC notify target: %s", zd.ZoneName, target)
			}

			port := dsc.Notify.Port
			if port == 0 {
				return fmt.Errorf("zone %s: no notify port found, config broken", zd.ZoneName)
			}

			notifyTypes := dsc.Notify.Types
			if len(notifyTypes) == 0 {
				return fmt.Errorf("zone %s: no notify types found, config broken", zd.ZoneName)
			}
			for _, t := range notifyTypes {
				foo := fmt.Sprintf("_dsync.%s %d IN DSYNC %s %s %d %s", replacer, ttl, t, s, port, target)
				dsyncrr, err := dns.NewRR(foo)
				if err != nil {
					lg.Error("failed to create DSYNC RR", "rr", foo, "err", err)
					return err
				}
				rrset.RRs = append(rrset.RRs, dsyncrr)
				dsync_added = true
			}

			notifyAddresses := dsc.Notify.Addresses
			if len(notifyAddresses) == 0 {
				return fmt.Errorf("zone %s: no notify addresses found, config broken", zd.ZoneName)
			}
			for _, addr := range notifyAddresses {
				if err := MaybeAddAddressRR(target, addr); err != nil {
					return err
				}
			}

		case "UPDATE":
			replacer := zd.ZoneName
			if replacer == "." {
				replacer = "root"
			}
			target := dns.Fqdn(strings.Replace(dsc.Update.Target, "{ZONENAME}", replacer, 1))
			if _, ok := dns.IsDomainName(target); !ok {
				return fmt.Errorf("zone %s: invalid DSYNC update target: %s", zd.ZoneName, target)
			}

			port := dsc.Update.Port
			if port == 0 {
				return fmt.Errorf("zone %s: no update port found, config broken", zd.ZoneName)
			}

			updateTypes := dsc.Update.Types
			if len(updateTypes) == 0 {
				return fmt.Errorf("zone %s: no update types found, config broken", zd.ZoneName)
			}
			for _, t := range updateTypes {
				foo := fmt.Sprintf("_dsync.%s %d IN DSYNC %s %s %d %s", replacer, ttl, t, s, port, target)
				dsyncrr, err := dns.NewRR(foo)
				if err != nil {
					lg.Error("failed to create DSYNC RR", "rr", foo, "err", err)
					return err
				}
				rrset.RRs = append(rrset.RRs, dsyncrr)
				dsync_added = true
			}

			updateAddresses := dsc.Update.Addresses
			if len(updateAddresses) == 0 {
				return fmt.Errorf("zone %s: no update addresses found, config broken", zd.ZoneName)
			}
			for _, addr := range updateAddresses {
				if err := MaybeAddAddressRR(target, addr); err != nil {
					return err
				}
			}

		case "API":
			// Unlike NOTIFY and UPDATE, the target is not a host that
			// receives DNS: it is where the service description lives. The
			// DSYNC record points at it, and the URI and TXT published there
			// say what the endpoint is and what dialect it speaks.
			//
			// All three go into the same UpdateRequest below, and that is
			// load bearing rather than tidiness: a child that resolved the
			// DSYNC record but not yet the URI cannot do anything except
			// fail. One update, one serial bump, all three visible together.
			apiconf := dsc.Api.WithDefaults()
			if err := apiconf.Validate(); err != nil {
				return fmt.Errorf("zone %s: %v", zd.ZoneName, err)
			}

			replacer := zd.ZoneName
			if replacer == "." {
				replacer = "root"
			}
			target := dns.Fqdn(strings.Replace(apiconf.Target, "{ZONENAME}", replacer, 1))
			if _, ok := dns.IsDomainName(target); !ok {
				return fmt.Errorf("zone %s: invalid DSYNC api target: %s", zd.ZoneName, target)
			}

			for _, t := range apiconf.Types {
				foo := fmt.Sprintf("_dsync.%s %d IN DSYNC %s %s %d %s", replacer, ttl, t, s, apiconf.Port, target)
				dsyncrr, err := dns.NewRR(foo)
				if err != nil {
					lg.Error("failed to create DSYNC RR", "rr", foo, "err", err)
					return err
				}
				rrset.RRs = append(rrset.RRs, dsyncrr)
				dsync_added = true
			}

			uriRR, err := dsyncApiUriRR(target, apiconf, uint32(ttl))
			if err != nil {
				return fmt.Errorf("zone %s: %v", zd.ZoneName, err)
			}
			txtRR := dsyncApiTxtRR(target, apiconf, uint32(ttl))
			rrset.RRs = append(rrset.RRs, uriRR, txtRR)
			lg.Info("added DSYNC API service description", "zone", zd.ZoneName,
				"target", target, "uri", uriRR.Target, "dialect", apiconf.Dialect)

			// Optional for this scheme: the URI's authority resolves by
			// ordinary means, and is often a name this zone does not serve.
			for _, addr := range apiconf.Addresses {
				if err := MaybeAddAddressRR(target, addr); err != nil {
					return err
				}
			}

		default:
			lg.Warn("unknown DSYNC scheme, ignoring", "scheme", scheme)
			continue
		}
	}

	if !dsync_added {
		// Every configured scheme is already published: nothing to do, and not
		// an error. Only a zone that ends up with no DSYNC records at all has
		// a broken configuration worth reporting.
		if alreadyPublished > 0 {
			lg.Debug("every configured DSYNC scheme is already published, nothing to do",
				"zone", zd.ZoneName, "records", alreadyPublished)
			return nil
		}
		return fmt.Errorf("no DSYNC RRs added for zone %s", zd.ZoneName)
	}

	// Publish SVCB bootstrap capability record at the DSYNC UPDATE target.
	// This advertises which bootstrap methods the parent supports, per
	// draft-ietf-dnsop-delegation-mgmt-via-ddns-01, section "SvcParamKey bootstrap".
	bootstrapMethods := dsc.Bootstrap.Methods
	if bootstrapMethods != "" {
		updateTarget := dsc.Update.Target
		if updateTarget != "" {
			replacer := zd.ZoneName
			if replacer == "." {
				replacer = "root"
			}
			target := dns.Fqdn(strings.Replace(updateTarget, "{ZONENAME}", replacer, 1))
			svcbRR := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: target, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Priority: 0,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBLocal{
						KeyCode: dns.SVCBKey(SvcbBootstrapKey),
						Data:    []byte(bootstrapMethods),
					},
				},
			}
			rrset.RRs = append(rrset.RRs, svcbRR)
			lg.Debug("added SVCB bootstrap record", "zone", zd.ZoneName, "target", target, "methods", bootstrapMethods)
		}
	}

	ur := UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Description:    fmt.Sprintf("Publish DSYNC RRs for zone %s", zd.ZoneName),
		Actions:        rrset.RRs,
		InternalUpdate: true,
	}

	for _, addr_rr := range addr_rrs {
		new_addr := false
		owner, err := zd.GetOwner(addr_rr.Header().Name)
		if err != nil {
			return fmt.Errorf("error fetching owner for address %s: %v", addr_rr.Header().Name, err)
		}

		if owner == nil {
			owner = &OwnerData{
				Name:    addr_rr.Header().Name,
				RRtypes: NewRRTypeStore(),
			}
		}

		rrtype := addr_rr.Header().Rrtype
		if _, exists := owner.RRtypes.Get(rrtype); !exists {
			new_addr = true
		} else {
			duplicate := false
			for _, existing_rr := range owner.RRtypes.GetOnlyRRSet(rrtype).RRs {
				if dns.IsDuplicate(existing_rr, addr_rr) {
					duplicate = true
					break
				}
			}
			if !duplicate {
				new_addr = true
			}
		}
		if new_addr {
			ur.Actions = append(ur.Actions, addr_rr)
		}
	}

	select {
	case zd.KeyDB.UpdateQ <- ur:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("PublishDsyncRRs: timeout sending update for zone %s", zd.ZoneName)
	}

	return nil
}

// DsyncUpdateTargetName computes the DSYNC UPDATE target name for a parent zone
// from the global config. Returns empty string if not configured.
func DsyncUpdateTargetName(zonename string) string {
	tpl := DelegationSyncConfig().Parent.Update.Target
	if tpl == "" {
		return ""
	}
	replacer := zonename
	if replacer == "." {
		replacer = "root"
	}
	return dns.Fqdn(strings.Replace(tpl, "{ZONENAME}", replacer, 1))
}

func (zd *ZoneData) UnpublishDsyncRRs() error {
	// A placeholder DSYNC record, used only to carry the owner name and type
	// into a delete. The class is set to ClassANY immediately below, which
	// removes the entire RRset, so none of the rdata values matter -- but the
	// string still has to PARSE, and DSYNC rdata is Type, Scheme, Port, Target
	// (see core/rr_dsync.go). The previous form omitted the leading type field
	// and quoted the scheme, so dns.NewRR failed on every zone and unpublish
	// could never do anything at all.
	dsync_str := fmt.Sprintf("_dsync.%s 0 IN DSYNC CDS NOTIFY 53 .", zd.ZoneName)

	anti_dsync, err := dns.NewRR(dsync_str)
	if err != nil {
		return fmt.Errorf("failed to create DSYNC RR: %v", err)
	}
	anti_dsync.Header().Class = dns.ClassANY // Delete DSYNC RRset

	actions := []dns.RR{anti_dsync}

	// The API scheme's service description lives at a separate name, so
	// dropping the DSYNC RRset alone would leave a URI and TXT behind
	// advertising an endpoint nothing points at any more. Removed in the same
	// update, in the same order they were published.
	if apiTarget := DsyncApiTargetName(zd.ZoneName); apiTarget != "" {
		anti_uri := &dns.URI{
			Hdr: dns.RR_Header{Name: apiTarget, Rrtype: dns.TypeURI, Class: dns.ClassANY},
		}
		anti_txt := &dns.TXT{
			Hdr: dns.RR_Header{Name: apiTarget, Rrtype: dns.TypeTXT, Class: dns.ClassANY},
		}
		actions = append(actions, anti_uri, anti_txt)
	}

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        actions,
		InternalUpdate: true,
	}:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("UnpublishDsyncRRs: timeout sending update for zone %s", zd.ZoneName)
	}

	return nil
}
