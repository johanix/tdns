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
	"github.com/spf13/viper"
)

func (zd *ZoneData) PublishDsyncRRs() error {
	lg.Debug("PublishDsyncRRs", "zone", zd.ZoneName)
	rrset := core.RRset{
		Name: zd.ZoneName,
	}

	// Verify that there is no DSYNC RRset already present
	owner, err := zd.GetOwner("_dsync." + zd.ZoneName)
	if err != nil {
		return fmt.Errorf("PublishDsyncRRs: error fetching _dsync owner for zone %s: %v", zd.ZoneName, err)
	}
	if owner != nil {
		rrset.RRs = owner.RRtypes.GetOnlyRRSet(core.TypeDSYNC).RRs
		if len(rrset.RRs) > 0 {
			lg.Debug("DSYNC RRset already present, not synthesizing", "zone", zd.ZoneName)
			return nil
		}
	}

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

	schemes := viper.GetStringSlice("delegationsync.parent.schemes")
	lg.Debug("defined DSYNC schemes", "zone", zd.ZoneName, "schemes", schemes)

	for _, scheme := range schemes {
		lg.Debug("checking DSYNC scheme", "zone", zd.ZoneName, "scheme", scheme)
		switch s := strings.ToUpper(scheme); s {
		case "NOTIFY":
			replacer := zd.ZoneName
			if replacer == "." {
				replacer = "root"
			}
			target := dns.Fqdn(strings.Replace(viper.GetString("delegationsync.parent.notify.target"), "{ZONENAME}", replacer, 1))
			if _, ok := dns.IsDomainName(target); !ok {
				return fmt.Errorf("zone %s: invalid DSYNC notify target: %s", zd.ZoneName, target)
			}

			port := uint16(viper.GetInt("delegationsync.parent.notify.port"))
			if port == 0 {
				return fmt.Errorf("zone %s: no notify port found, config broken", zd.ZoneName)
			}

			notifyTypes := viper.GetStringSlice("delegationsync.parent.notify.types")
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

			notifyAddresses := viper.GetStringSlice("delegationsync.parent.notify.addresses")
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
			target := dns.Fqdn(strings.Replace(viper.GetString("delegationsync.parent.update.target"), "{ZONENAME}", replacer, 1))
			if _, ok := dns.IsDomainName(target); !ok {
				return fmt.Errorf("zone %s: invalid DSYNC update target: %s", zd.ZoneName, target)
			}

			port := uint16(viper.GetInt("delegationsync.parent.update.port"))
			if port == 0 {
				return fmt.Errorf("zone %s: no update port found, config broken", zd.ZoneName)
			}

			updateTypes := viper.GetStringSlice("delegationsync.parent.update.types")
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

			updateAddresses := viper.GetStringSlice("delegationsync.parent.update.addresses")
			if len(updateAddresses) == 0 {
				return fmt.Errorf("zone %s: no update addresses found, config broken", zd.ZoneName)
			}
			for _, addr := range updateAddresses {
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
		return fmt.Errorf("no DSYNC RRs added for zone %s", zd.ZoneName)
	}

	// Publish SVCB bootstrap capability record at the DSYNC UPDATE target.
	// This advertises which bootstrap methods the parent supports, per
	// draft-ietf-dnsop-delegation-mgmt-via-ddns-01, section "SvcParamKey bootstrap".
	bootstrapMethods := viper.GetString("delegationsync.parent.bootstrap.methods")
	if bootstrapMethods != "" {
		updateTarget := viper.GetString("delegationsync.parent.update.target")
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
	tpl := viper.GetString("delegationsync.parent.update.target")
	if tpl == "" {
		return ""
	}
	replacer := zonename
	if replacer == "." {
		replacer = "root"
	}
	return dns.Fqdn(strings.Replace(tpl, "{ZONENAME}", replacer, 1))
}

// ZoneIsReady returns a function that can be used as a PreCondition for a DeferredUpdate.
// The returned function will return true if the zone exists and is ready, otherwise false.
func ZoneIsReady(zonename string) func() bool {
	return func() bool {
		_, ok := Zones.Get(zonename)
		return ok
	}
}

func (zd *ZoneData) UnpublishDsyncRRs() error {
	// Create a string representation of an empty DSYNC record for deletion
	dsync_str := fmt.Sprintf("_dsync.%s 0 IN DSYNC \"NOTIFY\" 53 1.2.3.4", zd.ZoneName)

	anti_dsync, err := dns.NewRR(dsync_str)
	if err != nil {
		return fmt.Errorf("failed to create DSYNC RR: %v", err)
	}
	anti_dsync.Header().Class = dns.ClassANY // Delete DSYNC RRset

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{anti_dsync},
		InternalUpdate: true,
	}:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("UnpublishDsyncRRs: timeout sending update for zone %s", zd.ZoneName)
	}

	return nil
}
