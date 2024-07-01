/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// Only used from CLI (tdns-cli ddns sync)
// Returns unsynched bool, adds, removes []dns.RR, error

// XXX: This requires lots of recursive queries and does not take advantage of the zonedata struct
//      in tdnsd most likely having cached most of this information. Since the only reason for
//      the tdns-cli tool is to interact with tdnsd, it really should leverage from that rather
//      than just do everything in the CLI.

func xxxChildDelegationDataUnsynched(zone, pzone, childpri, parpri string) (bool, []dns.RR, []dns.RR, error) {

	var differ bool
	var adds, removes []dns.RR

	if viper.GetBool("childsync.update-ns") {
		differ, adds, removes = ComputeRRDiff(childpri, parpri,
			Globals.Zonename, dns.TypeNS)
	} else {
		fmt.Printf("*** Note: configured NOT to update NS RRset.\n")
	}

	child_ns_inb, parent_ns_inb := ComputeBailiwickNS(childpri, parpri,
		Globals.Zonename)
	for _, ns := range child_ns_inb {
		fmt.Printf("Child in-bailiwick NS: %s\n", ns)
	}
	for _, ns := range parent_ns_inb {
		fmt.Printf("Parent in-bailiwick NS: %s\n", ns)
	}

	for _, ns := range child_ns_inb {
		if viper.GetBool("childsync.update-a") {
			fmt.Printf("Comparing A glue for child NS %s:\n", ns)
			gluediff, a_glue_adds, a_glue_removes := ComputeRRDiff(childpri,
				parpri, ns, dns.TypeA)
			if gluediff {
				differ = true
				for _, rr := range a_glue_removes {
					removes = append(removes, rr)
				}
				for _, rr := range a_glue_adds {
					adds = append(adds, rr)
				}
			}
		} else {
			fmt.Printf("*** Note: configured NOT to update A glue.\n")
		}

		if viper.GetBool("childsync.update-aaaa") {
			fmt.Printf("Comparing AAAA glue for child NS %s:\n", ns)
			gluediff, aaaa_glue_adds, aaaa_glue_removes := ComputeRRDiff(childpri,
				parpri, ns, dns.TypeAAAA)
			if gluediff {
				differ = true
				for _, rr := range aaaa_glue_removes {
					removes = append(removes, rr)
				}
				for _, rr := range aaaa_glue_adds {
					adds = append(adds, rr)
				}
			}
		} else {
			fmt.Printf("*** Note: configured NOT to update AAAA glue.\n")
		}
	}

	if !differ {
		fmt.Printf("Parent delegation data is in sync with child. No update needed.\n")
		return false, []dns.RR{}, []dns.RR{}, nil
	}
	return true, adds, removes, nil
}

// XXX: This is similar to ChildDelegationDataUnsynched, but instead of querying the
//      child and parent primaries we compare the delegation data in the *ZoneData
//      structs.

// DelegationDataChanged() compares the delegation data in the old vs new *ZoneData structs.
// Returns unsynched bool, adds, removes []dns.RR, error
func (zd *ZoneData) xxxDelegationDataChanged(newzd *ZoneData) (bool, []dns.RR, []dns.RR, error) {
	Globals.Zonename = zd.ZoneName

	var differ, fakeolddata bool
	var adds, removes []dns.RR

	oldapex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, []dns.RR{}, []dns.RR{},
			fmt.Errorf("Error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	if oldapex == nil {
		if !viper.GetBool("childsync.sync-on-boot") {
			zd.Logger.Printf("DelDataChanged: Zone %s old apexdata was nil. Claiming this is a non-change.",
				zd.ZoneName)
			return false, []dns.RR{}, []dns.RR{}, nil
		}
		zd.Logger.Printf("Zone %s delegation sync-on-boot: faking empty old apex data", zd.ZoneName)
		fakeolddata = true
		oldapex = &OwnerData{
			Name: zd.ZoneName,
			RRtypes: map[uint16]RRset{
				dns.TypeNS:   RRset{},
				dns.TypeA:    RRset{},
				dns.TypeAAAA: RRset{},
			},
		}
	}

	newapex, err := newzd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, []dns.RR{}, []dns.RR{},
			fmt.Errorf("Error from newzd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	if viper.GetBool("childsync.update-ns") {
		differ, adds, removes = RRsetDiffer(zd.ZoneName, newapex.RRtypes[dns.TypeNS].RRs,
			oldapex.RRtypes[dns.TypeNS].RRs,
			dns.TypeNS, zd.Logger)
	} else {
		zd.Logger.Printf("*** Note: configured NOT to update NS RRset.\n")
	}

	//	new_ns_inb, old_ns_inb := ComputeBailiwickNS_NG(newapex.RRtypes[dns.TypeNS].RRs,
	//		oldapex.RRtypes[dns.TypeNS].RRs, zd.ZoneName)
	new_ns_inb, _ := BailiwickNS(zd.ZoneName, newapex.RRtypes[dns.TypeNS].RRs)
	old_ns_inb, _ := BailiwickNS(zd.ZoneName, oldapex.RRtypes[dns.TypeNS].RRs)
	for _, ns := range new_ns_inb {
		zd.Logger.Printf("New in-bailiwick NS: %s\n", ns)
	}
	for _, ns := range old_ns_inb {
		zd.Logger.Printf("Old in-bailiwick NS: %s\n", ns)
	}

	var oldowner *OwnerData
	for _, ns := range new_ns_inb {
		if fakeolddata {
			oldowner = oldapex
		} else {
			oldowner, err = zd.GetOwner(ns)
		}
		if err != nil {
			return false, []dns.RR{}, []dns.RR{},
				fmt.Errorf("Error from zd.GetOwner(%s): %v", ns, err)
		}
		newowner, err := newzd.GetOwner(ns)
		if err != nil {
			return false, []dns.RR{}, []dns.RR{},
				fmt.Errorf("Error from newzd.GetOwner(%s): %v", ns, err)
		}

		if viper.GetBool("childsync.update-a") {
			zd.Logger.Printf("Comparing A glue for new NS %s:\n", ns)

			gluediff, a_glue_adds, a_glue_removes := RRsetDiffer(ns,
				newowner.RRtypes[dns.TypeA].RRs,
				oldowner.RRtypes[dns.TypeA].RRs,
				dns.TypeA, zd.Logger)
			if gluediff {
				differ = true
				for _, rr := range a_glue_removes {
					removes = append(removes, rr)
				}
				for _, rr := range a_glue_adds {
					adds = append(adds, rr)
				}
			}
		} else {
			zd.Logger.Printf("*** Note: configured NOT to update A glue.\n")
		}

		if viper.GetBool("childsync.update-aaaa") {
			zd.Logger.Printf("Comparing AAAA glue for new NS %s:\n", ns)
			gluediff, aaaa_glue_adds, aaaa_glue_removes := RRsetDiffer(ns,
				newowner.RRtypes[dns.TypeAAAA].RRs,
				oldowner.RRtypes[dns.TypeAAAA].RRs,
				dns.TypeAAAA, zd.Logger)
			if gluediff {
				differ = true
				for _, rr := range aaaa_glue_removes {
					removes = append(removes, rr)
				}
				for _, rr := range aaaa_glue_adds {
					adds = append(adds, rr)
				}
			}
		} else {
			fmt.Printf("*** Note: configured NOT to update AAAA glue.\n")
		}
	}

	if !differ {
		fmt.Printf("Old delegation data is identical to new. No update needed.\n")
		return false, []dns.RR{}, []dns.RR{}, nil
	}
	return true, adds, removes, nil
}

// This is only called from the CLI command "tdns-cli ddns sync" and uses a SIG(0) key from the
// command line rather than the one in the keystore. Not to be used by TDNSD.
func ChildSendDdnsSync(pzone string, target *DsyncTarget, adds, removes []dns.RR) error {
	//	const update_scheme = 2
	//	dsynctarget, err := LookupDSYNCTarget(pzone, parpri, dns.StringToType["ANY"], update_scheme)
	//	if err != nil {
	//		log.Fatalf("Error from LookupDSYNCTarget(%s, %s): %v", pzone, parpri, err)
	//	}

	msg, err := CreateUpdate(pzone, Globals.Zonename, adds, removes)
	if err != nil {
		log.Fatalf("Error from CreateUpdate(%s): %v", pzone, err)
	}

	keyrr, cs := LoadSigningKey(Globals.Sig0Keyfile)
	var smsg *dns.Msg

	if Globals.Sig0Keyfile != "" {
		fmt.Printf("Signing update.\n")
		smsg, err = SignMsgNG(*msg, Globals.Zonename, &cs, keyrr)
		if err != nil {
			log.Printf("Error from SignMsgNG(%s): %v", Globals.Zonename, err)
			return err
		}
	} else {
		fmt.Printf("Keyfile not specified, not signing message.\n")
	}

	rcode, err := SendUpdate(smsg, pzone, target)
	if err != nil {
		log.Printf("Error from SendUpdate(%s): %v", target, err)
		return err
	} else {
		log.Printf("SendUpdate(parent=%s, target=%s) returned rcode %s", pzone, target, dns.RcodeToString[rcode])
	}
	return nil
}

func SendUpdate(msg *dns.Msg, zonename string, target *DsyncTarget) (int, error) {
	if zonename == "." {
		log.Printf("Error: zone name not specified. Terminating.\n")
		return 0, fmt.Errorf("zone name not specified")
	}

	log.Printf("SendUpdate(%s, %s) target has addresses: %v", zonename, target.Name, target.Addresses)

	for _, dst := range target.Addresses {
		if Globals.Verbose {
			log.Printf("Sending DNS UPDATE for parent zone %s to %s on address %s:%d\n", zonename, target.Name, dst, target.Port)
		}

		if Globals.Debug {
			log.Printf("Sending Update:\n%s\n", msg.String())
		}

		dst = net.JoinHostPort(dst, fmt.Sprintf("%d", target.Port))
		res, err := dns.Exchange(msg, dst)
		if err != nil {
			log.Printf("Error from dns.Exchange(%s, UPDATE): %v. Trying next address", dst, err)
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			if Globals.Verbose {
				log.Printf("... and got rcode %s back (bad)\n", dns.RcodeToString[res.Rcode])
			}
			log.Printf("Error from %s: Rcode: %s. Trying next address", dst, dns.RcodeToString[res.Rcode])
			// return res.Rcode, fmt.Errorf("Rcode: %s", dns.RcodeToString[res.Rcode])
			continue
		} else {
			if Globals.Verbose {
				log.Printf("... and got rcode NOERROR back (good)\n")
			}
			return res.Rcode, nil
		}
	}
	return 0, fmt.Errorf("Error: none of the targets %v were reachable", target.Addresses)
}

func CreateUpdate(parent, child string, adds, removes []dns.RR) (*dns.Msg, error) {
	if parent == "." || parent == "" {
		return nil, fmt.Errorf("Error: parent zone name not specified. Terminating.")
	}
	if child == "." || child == "" {
		return nil, fmt.Errorf("Error: child zone name not specified. Terminating.")
	}

	m := new(dns.Msg)
	m.SetUpdate(parent)

	m.Remove(removes)
	m.Insert(adds)

	for _, nsr := range removes {
		if ns, ok := nsr.(*dns.NS); ok { // if removing an NS, then also remove any glue
			if strings.HasSuffix(ns.Ns, child) {
				rrA := new(dns.A)
				rrA.Hdr = dns.RR_Header{Name: ns.Ns, Rrtype: dns.TypeA, Class: dns.ClassANY, Ttl: 3600}
				rrAAAA := new(dns.AAAA)
				rrAAAA.Hdr = dns.RR_Header{Name: ns.Ns, Rrtype: dns.TypeAAAA, Class: dns.ClassANY, Ttl: 3600}
				m.RemoveRRset([]dns.RR{rrA, rrAAAA})
			}
		}
	}

	if Globals.Debug {
		fmt.Printf("Creating update msg:\n%s\n", m.String())
	}
	return m, nil
}

// Only used in the CLI version
func ComputeRRDiff(childpri, parpri, owner string, rrtype uint16) (bool, []dns.RR, []dns.RR) {
	if Globals.Debug {
		//	fmt.Printf("*** ComputeRRDiff(%s, %s)\n", owner, dns.TypeToString[rrtype])
		fmt.Printf("*** ComputeRRDiff(%s, %s, %s, %s)\n", childpri, parpri, owner, dns.TypeToString[rrtype])
	}
	rrname := dns.TypeToString[rrtype]
	rrs_parent, err := AuthQuery(owner, parpri, rrtype)
	if err != nil {
		log.Fatalf("Error: looking up child %s %s RRset in parent primary \"%s\": %v",
			Globals.Zonename, rrname, parpri, err)
	}

	rrs_child, err := AuthQuery(owner, childpri, rrtype)
	if err != nil {
		log.Fatalf("Error: looking up child %s %s RRset in child primary \"%s\": %v",
			Globals.Zonename, rrname, childpri, err)
	}

	fmt.Printf("%d %s RRs from parent, %d %s RRs from child\n",
		len(rrs_parent), rrname, len(rrs_child), rrname)
	if Globals.Debug {
		for _, rrp := range rrs_parent {
			fmt.Printf("Parent: %s\n", rrp.String())
		}

		for _, rrc := range rrs_child {
			fmt.Printf("Child:  %s\n", rrc.String())
		}
	}

	differ, adds, removes := RRsetDiffer(owner, rrs_child, rrs_parent, rrtype, log.Default())
	if differ {
		fmt.Printf("Parent and child %s RRsets differ. To get parent in sync:\n", rrname)
		for _, rr := range removes {
			fmt.Printf("Remove: %s\n", rr.String())
		}
		for _, rr := range adds {
			fmt.Printf("Add:   %s\n", rr.String())
		}
	}
	return differ, adds, removes
}

// XXX: Should be replaced by four calls: one per child and parent primary to get
//
//	the NS RRsets and one to new ComputeBailiwickNS() that takes a []dns.RR + zone name
func ComputeBailiwickNS(childpri, parpri, owner string) ([]string, []string) {
	ns_parent, err := AuthQuery(owner, parpri, dns.TypeNS)
	if err != nil {
		log.Fatalf("Error: looking up child %s NS RRset in parent primary %s: %v",
			Globals.Zonename, parpri, err)
	}

	ns_child, err := AuthQuery(Globals.Zonename, childpri, dns.TypeNS)
	if err != nil {
		log.Fatalf("Error: looking up child %s NS RRset in child primary %s: %v",
			Globals.Zonename, childpri, err)
	}

	fmt.Printf("%d NS RRs from parent, %d NS RRs from child\n",
		len(ns_parent), len(ns_child))
	if Globals.Debug {
		for _, rrp := range ns_parent {
			fmt.Printf("Parent: %s\n", rrp.String())
		}

		for _, rrc := range ns_child {
			fmt.Printf("Child:  %s\n", rrc.String())
		}
	}

	// return ComputeBailiwickNS_NG(ns_child, ns_parent, owner)
	child_inb, _ := BailiwickNS(owner, ns_child)
	parent_inb, _ := BailiwickNS(owner, ns_parent)
	return child_inb, parent_inb
}

// Return the names of NS RRs that are in bailiwick for the zone.
func BailiwickNS(zonename string, nsrrs []dns.RR) ([]string, error) {
	var ns_inbailiwick []string
	for _, rr := range nsrrs {
		if ns, ok := rr.(*dns.NS); ok {
			if strings.HasSuffix(ns.Ns, zonename) {
				ns_inbailiwick = append(ns_inbailiwick, ns.Ns)
			}
		}
	}
	return ns_inbailiwick, nil
}

func xxxComputeBailiwickNS_NG(newnsrrset, oldnsrrset []dns.RR, owner string) ([]string, []string) {
	fmt.Printf("%d old NS RRs, %d new NS RRs\n", len(oldnsrrset), len(newnsrrset))
	if Globals.Debug {
		for _, rrp := range oldnsrrset {
			fmt.Printf("Parent: %s\n", rrp.String())
		}

		for _, rrc := range newnsrrset {
			fmt.Printf("Child:  %s\n", rrc.String())
		}
	}

	var old_ns_inb, new_ns_inb []string

	for _, rr := range oldnsrrset {
		if ns, ok := rr.(*dns.NS); ok {
			if strings.HasSuffix(ns.Ns, owner) {
				old_ns_inb = append(old_ns_inb, ns.Ns)
			}
		}
	}
	for _, rr := range newnsrrset {
		if ns, ok := rr.(*dns.NS); ok {
			if strings.HasSuffix(ns.Ns, owner) {
				new_ns_inb = append(new_ns_inb, ns.Ns)
			}
		}
	}

	return new_ns_inb, old_ns_inb
}

// func (zd *ZoneData) SyncWithParent(adds, removes []dns.RR) error {
//	zd.Logger.Printf("SyncWithParent: zone=%s adds=%v removes=%v", zd.ZoneName, adds, removes)

//	scheme, dsynctarget, err := zd.BestSyncScheme()
//	if err != nil {
//		return err
//	}
//	zd.Logger.Printf("*** SyncWithParent: will try %s scheme using: %s. Target: %v", scheme, dsyncrr, dsynctarget)

// Ok, so let's do it:
//	return nil
// }

// Find the best scheme (from the POV of the child) to sync the deletation with the parent
func (zd *ZoneData) BestSyncScheme() (string, *DsyncTarget, error) {
	var active_drr *DSYNC
	var active_scheme string
	var dsynctarget DsyncTarget

	zd.Logger.Printf("BestSyncScheme: imr=%s zone=%s", Globals.IMR, zd.ZoneName)

	// dsync_rrs, parent, err := DsyncDiscovery(zd.ZoneName, Globals.IMR, Globals.Verbose)
	dsync_res, err := DsyncDiscovery(zd.ZoneName, Globals.IMR, Globals.Verbose)
	if err != nil {
		zd.Logger.Printf("SyncWithParent: Error from DsyncDiscovery(): %v", err)
		return "", nil, err
	}
	if len(dsync_res.Rdata) == 0 {
		msg := fmt.Sprintf("No DSYNC RRs for %s found in parent %s.", zd.ZoneName, dsync_res.Parent)
		zd.Logger.Printf("SyncWithParent: %s. Synching not possible.", msg)
		return "", nil, fmt.Errorf("Error: %s", msg)
	}
	schemes := viper.GetStringSlice("childsync.schemes")
	if len(schemes) == 0 {
		zd.Logger.Printf("SyncWithParent: Error: no syncronization schemes configured for child %s", zd.ZoneName)
		return "", nil, fmt.Errorf("No synchronizations schemes configured for child %s", zd.ZoneName)
	}

	for _, scheme := range schemes {
		scheme = strings.ToLower(scheme)

		switch scheme {
		case "update":
			log.Printf("BestSyncScheme(): checking UPDATE alternative:")
			for _, drr := range dsync_res.Rdata {
				if drr.Scheme == SchemeUpdate {
					active_drr = drr
					break
				}
			}
			if active_drr != nil {
				log.Printf("BestSyncSchemes: found working UPDATE config, happy with that.")
				active_scheme = "UPDATE"
				break
			}

		case "notify":
			if active_scheme != "" {
				break
			}
			log.Printf("BestSyncScheme(): checking NOTIFY alternative:")
			for _, drr := range dsync_res.Rdata {
				if drr.Scheme == 1 && drr.Type == dns.TypeCSYNC {
					active_drr = drr
					break
				}
			}
			if active_drr != nil {
				active_scheme = "NOTIFY"
				break
			}

		default:
			msg := fmt.Sprintf("Error: zone %s unknown child scheme: %s", zd.ZoneName, scheme)
			zd.Logger.Printf(msg)
			return "", nil, fmt.Errorf(msg)
		}
	}

	zd.Logger.Printf("BestSyncScheme: zone %s parent %s. DSYNC alternatives are:", zd.ZoneName, dsync_res.Parent)
	for _, drr := range dsync_res.Rdata {
		zd.Logger.Printf("%s", drr.String())
	}

	dsynctarget.Addresses, err = net.LookupHost(active_drr.Target)
	if err != nil {
		return "", nil, fmt.Errorf("Error: %v", err)
	}

	if Globals.Verbose {
		fmt.Printf("%s has the IP addresses: %v\n", active_drr.Target, dsynctarget.Addresses)
	}
	dsynctarget.Port = active_drr.Port
	dsynctarget.Name = active_drr.Target
	dsynctarget.RR = active_drr

	zd.Logger.Printf("BestSyncScheme: Best DSYNC alternative: %s:", active_drr.String())
	return active_scheme, &dsynctarget, nil
}
