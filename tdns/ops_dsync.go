/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (zd *ZoneData) PublishDsyncRRs() error {
	zd.Logger.Printf("PublishDsyncRRs: zone: %s", zd.ZoneName)
	rrset := RRset{
		Name: zd.ZoneName,
	}

	// Verify that there is no DSYNC RRset already present
	owner, _ := zd.GetOwner("_dsync." + zd.ZoneName)
	if owner != nil {
		rrset.RRs = owner.RRtypes.GetOnlyRRSet(TypeDSYNC).RRs
		if len(rrset.RRs) > 0 {
			zd.Logger.Printf("PublishDsyncRRs: zone: %s DSYNC RRset already present; not synthesizing DSYNC RRset", zd.ZoneName)
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
			zd.Logger.Printf("Error from NewRR(%s): %v", addrstr, err)
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

	// if zd.Debug {
	zd.Logger.Printf("PublishDsyncRRs: zone: %s defined DSYNC schemes: %v", zd.ZoneName, viper.GetStringSlice("delegationsync.parent.schemes"))
	// }

	for _, scheme := range viper.GetStringSlice("delegationsync.parent.schemes") {
		// if zd.Debug {
		zd.Logger.Printf("PublishDsyncRRs: zone: %s checking DSYNC scheme: %s", zd.ZoneName, scheme)
		// }
		switch s := strings.ToUpper(scheme); s {
		case "NOTIFY":
			// zd.Logger.Printf("PublishDsyncRRs: zone: %s checking DSYNC scheme: %s", zd.ZoneName, scheme)
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
				zd.Logger.Printf("PublishDsyncRRs: zone: %s no notify port found", zd.ZoneName)
				return fmt.Errorf("zone %s: no notify port found. config broken", zd.ZoneName)
			}

			notifyTypes := viper.GetStringSlice("delegationsync.parent.notify.types")
			if len(notifyTypes) == 0 {
				zd.Logger.Printf("PublishDsyncRRs: zone: %s no notify types found", zd.ZoneName)
				return fmt.Errorf("zone %s: no notify types found. config broken", zd.ZoneName)
			}
			for _, t := range notifyTypes {
				foo := fmt.Sprintf("_dsync.%s %d IN DSYNC %s %s %d %s", replacer, ttl, t, s, port, target)
				dsyncrr, err := dns.NewRR(foo)
				if err != nil {
					zd.Logger.Printf("Error from NewRR(%s): %v", foo, err)
					return err
				}
				rrset.RRs = append(rrset.RRs, dsyncrr)
				dsync_added = true
			}

			notifyAddresses := viper.GetStringSlice("delegationsync.parent.notify.addresses")
			if len(notifyAddresses) == 0 {
				zd.Logger.Printf("PublishDsyncRRs: zone: %s no notify addresses found", zd.ZoneName)
				return fmt.Errorf("zone %s: no notify addresses found. config broken", zd.ZoneName)
			}
			for _, addr := range notifyAddresses {
				if err := MaybeAddAddressRR(target, addr); err != nil {
					zd.Logger.Printf("Error from MaybeAddAddressRR(%s, %s): %v", target, addr, err)
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
				zd.Logger.Printf("PublishDsyncRRs: zone: %s no update port found", zd.ZoneName)
				return fmt.Errorf("zone %s: no update port found. config broken", zd.ZoneName)
			}

			updateTypes := viper.GetStringSlice("delegationsync.parent.update.types")
			if len(updateTypes) == 0 {
				zd.Logger.Printf("PublishDsyncRRs: zone: %s no update types found", zd.ZoneName)
				return fmt.Errorf("zone %s: no update types found. config broken", zd.ZoneName)
			}
			for _, t := range updateTypes {
				foo := fmt.Sprintf("_dsync.%s %d IN DSYNC %s %s %d %s", replacer, ttl, t, s, port, target)
				dsyncrr, err := dns.NewRR(foo)
				if err != nil {
					zd.Logger.Printf("Error from NewRR(%s): %v", foo, err)
					return err
				}
				rrset.RRs = append(rrset.RRs, dsyncrr)
				dsync_added = true
			}

			updateAddresses := viper.GetStringSlice("delegationsync.parent.update.addresses")
			if len(updateAddresses) == 0 {
				zd.Logger.Printf("PublishDsyncRRs: zone: %s no update addresses found", zd.ZoneName)
				return fmt.Errorf("zone %s: no update addresses found. config broken", zd.ZoneName)
			}
			for _, addr := range updateAddresses {
				if err := MaybeAddAddressRR(target, addr); err != nil {
					zd.Logger.Printf("Error from MaybeAddAddressRR(%s, %s): %v", target, addr, err)
					return err
				}
			}

		default:
			zd.Logger.Printf("Error: unknown DSYNC scheme: \"%s\". Ignored.", scheme)
			continue
		}
	}

	if !dsync_added {
		return fmt.Errorf("no DSYNC RRs added for zone %s", zd.ZoneName)
	}

	ur := UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Description:    fmt.Sprintf("Publish DSYNC RRs for zone %s", zd.ZoneName),
		Actions:        rrset.RRs, // Add all the DSYNC RRs first.
		InternalUpdate: true,
	}

	for _, addr_rr := range addr_rrs {
		new_addr := false
		owner, err := zd.GetOwner(addr_rr.Header().Name)
		if err != nil {
			return fmt.Errorf("Error fetching owner for address %s: %v", addr_rr.Header().Name, err)
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

	zd.KeyDB.UpdateQ <- ur

	return nil
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

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{anti_dsync},
		InternalUpdate: true,
	}

	return nil
}
