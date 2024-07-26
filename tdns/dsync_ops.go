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
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("Zone %s does not allow updates. DSYNC publication not possible", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	rrset := RRset{
		Name: zd.ZoneName,
	}

	ttl := 7200
	addr_rrs := []dns.RR{}

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

	for _, scheme := range viper.GetStringSlice("delegationsync.parent.schemes") {
		switch s := strings.ToUpper(scheme); s {
		case "NOTIFY":
			target := dns.Fqdn(strings.Replace(viper.GetString("delegationsync.parent.notify.target"), "{ZONENAME}", zd.ZoneName, 1))
			if _, ok := dns.IsDomainName(target); !ok {
				return fmt.Errorf("Zone %s: Invalid DSYNC notify target: %s", zd.ZoneName, target)
			}
			port := uint16(viper.GetInt("delegationsync.parent.notify.port"))

			for _, t := range viper.GetStringSlice("delegationsync.parent.notify.types") {
				foo := fmt.Sprintf("_dsync.%s %d IN DSYNC %s %s %d %s", zd.ZoneName, ttl, t, s, port, target)
				dsyncrr, err := dns.NewRR(foo)
				if err != nil {
					zd.Logger.Printf("Error from NewRR(%s): %v", foo, err)
					return err
				}
				rrset.RRs = append(rrset.RRs, dsyncrr)
			}

			for _, addr := range viper.GetStringSlice("delegationsync.parent.notify.addresses") {
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

			for _, t := range viper.GetStringSlice("delegationsync.parent.update.types") {
				foo := fmt.Sprintf("_dsync.%s %d IN DSYNC %s %s %d %s", zd.ZoneName, ttl, t, s, port, target)
				dsyncrr, err := dns.NewRR(foo)
				if err != nil {
					zd.Logger.Printf("Error from NewRR(%s): %v", foo, err)
					return err
				}
				rrset.RRs = append(rrset.RRs, dsyncrr)
			}

			for _, addr := range viper.GetStringSlice("delegationsync.parent.update.addresses") {
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

	for _, addr_rr := range addr_rrs {
		owner, err := zd.GetOwner(addr_rr.Header().Name)
		if err != nil {
			return fmt.Errorf("Error fetching owner for address %s: %v", addr_rr.Header().Name, err)
		}

		if owner == nil {
			owner = &OwnerData{
				Name:    addr_rr.Header().Name,
				RRtypes: make(map[uint16]RRset),
			}
			zd.AddOwner(owner)
		}

		rrtype := addr_rr.Header().Rrtype
		if _, exists := owner.RRtypes[rrtype]; !exists {
			owner.RRtypes[rrtype] = RRset{
				Name:   addr_rr.Header().Name,
				RRs:    []dns.RR{addr_rr},
				RRSIGs: []dns.RR{},
			}
		} else {
			duplicate := false
			for _, existing_rr := range owner.RRtypes[rrtype].RRs {
				if dns.IsDuplicate(existing_rr, addr_rr) {
					duplicate = true
					break
				}
			}
			if !duplicate {
				zd.mu.Lock()
				tmp := owner.RRtypes[rrtype]
				tmp.RRs = append(tmp.RRs, addr_rr)
				owner.RRtypes[rrtype] = tmp
				zd.mu.Unlock()
			}
		}
	}

	zd.mu.Lock()
	apex.RRtypes[TypeDSYNC] = rrset
	zd.Options["dirty"] = true
	zd.mu.Unlock()

	zd.BumpSerial()

	return nil
}

func (zd *ZoneData) UnpublishDsyncRRs() error {
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("Zone %s does not allow updates. DSYNC unpublication not possible", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	zd.mu.Lock()
	delete(apex.RRtypes, dns.TypeCSYNC)
	zd.Options["dirty"] = true
	zd.mu.Unlock()

	zd.BumpSerial()

	return nil
}
