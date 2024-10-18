/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (zd *ZoneData) PublishDsyncRRs() error {
	zd.Logger.Printf("PublishDsyncRRs: zone: %s", zd.ZoneName)
	rrset := RRset{
		Name: zd.ZoneName,
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
			zd.Logger.Printf("PublishDsyncRRs: zone: %s checking DSYNC scheme: %s", zd.ZoneName, scheme)
			target := dns.Fqdn(strings.Replace(viper.GetString("delegationsync.parent.notify.target"), "{ZONENAME}", zd.ZoneName, 1))
			if _, ok := dns.IsDomainName(target); !ok {
				return fmt.Errorf("Zone %s: Invalid DSYNC notify target: %s", zd.ZoneName, target)
			}

			port := uint16(viper.GetInt("delegationsync.parent.notify.port"))
			if port == 0 {
				zd.Logger.Printf("PublishDsyncRRs: zone: %s no notify port found", zd.ZoneName)
				return fmt.Errorf("Zone %s: No notify port found. Config broken", zd.ZoneName)
			}

			notifyTypes := viper.GetStringSlice("delegationsync.parent.notify.types")
			if len(notifyTypes) == 0 {
				zd.Logger.Printf("PublishDsyncRRs: zone: %s no notify types found", zd.ZoneName)
				return fmt.Errorf("Zone %s: No notify types found. Config broken", zd.ZoneName)
			}
			for _, t := range notifyTypes {
				foo := fmt.Sprintf("_dsync.%s %d IN DSYNC %s %s %d %s", zd.ZoneName, ttl, t, s, port, target)
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
				return fmt.Errorf("Zone %s: No notify addresses found. Config broken", zd.ZoneName)
			}
			for _, addr := range notifyAddresses {
				if err := MaybeAddAddressRR(target, addr); err != nil {
					zd.Logger.Printf("Error from MaybeAddAddressRR(%s, %s): %v", target, addr, err)
					return err
				}
			}

		case "UPDATE":
			target := dns.Fqdn(strings.Replace(viper.GetString("delegationsync.parent.update.target"), "{ZONENAME}", zd.ZoneName, 1))
			if _, ok := dns.IsDomainName(target); !ok {
				return fmt.Errorf("Zone %s: Invalid DSYNC update target: %s", zd.ZoneName, target)
			}

			port := uint16(viper.GetInt("delegationsync.parent.update.port"))
			if port == 0 {
				zd.Logger.Printf("PublishDsyncRRs: zone: %s no update port found", zd.ZoneName)
				return fmt.Errorf("Zone %s: No update port found. Config broken", zd.ZoneName)
			}

			updateTypes := viper.GetStringSlice("delegationsync.parent.update.types")
			if len(updateTypes) == 0 {
				zd.Logger.Printf("PublishDsyncRRs: zone: %s no update types found", zd.ZoneName)
				return fmt.Errorf("Zone %s: No update types found. Config broken", zd.ZoneName)
			}
			for _, t := range updateTypes {
				foo := fmt.Sprintf("_dsync.%s %d IN DSYNC %s %s %d %s", zd.ZoneName, ttl, t, s, port, target)
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
				return fmt.Errorf("Zone %s: No update addresses found. Config broken", zd.ZoneName)
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
		return fmt.Errorf("No DSYNC RRs added for zone %s", zd.ZoneName)
	}

	ur := UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
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
				RRtypes: NewConcurrentRRTypeStore(),
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

func (zd *ZoneData) UnpublishDsyncRRs() error {
	anti_dsync_rr, err := dns.NewRR("_dsync." + zd.ZoneName + " 7200 IN DSYNC ANY NOTIFY 53 1.2.3.4")
	if err != nil {
		return fmt.Errorf("Error from NewRR(%s): %v", "_dsync."+zd.ZoneName+" 7200 ANY DSYNC ANY NOTIFY 53 1.2.3.4", err)
	}
	// ClassANY == remove RRset
	anti_dsync_rr.Header().Class = dns.ClassANY // XXX: dns.NewRR fails to parse a CLASS ANY DSYNC RRset, so we set the class manually.
	log.Printf("Unpublishing DSYNC RRset: %s", anti_dsync_rr.String())

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{anti_dsync_rr},
		InternalUpdate: true,
	}

	return nil
}
