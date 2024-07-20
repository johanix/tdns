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

// This is only called from the CLI command "tdns-cli ddns sync" and uses a SIG(0) key from the
// command line rather than the one in the keystore. Not to be used by TDNSD.
func ChildSendDdnsSync(pzone string, target *DsyncTarget, adds, removes []dns.RR) error {
	msg, err := CreateChildUpdate(pzone, Globals.Zonename, adds, removes)
	if err != nil {
		return fmt.Errorf("Error from CreateChildUpdate(%s): %v", pzone, err)
	}

	pkc, err := LoadSig0SigningKey(Globals.Sig0Keyfile)
	if err != nil {
		log.Printf("Error from LoadSig0SigningKeyNG(%s): %v", Globals.Sig0Keyfile, err)
		return err
	}
	var smsg *dns.Msg
	sak := &Sig0ActiveKeys{
		Keys: []*PrivateKeyCache{pkc},
	}

	if Globals.Sig0Keyfile != "" {
		fmt.Printf("Signing update.\n")
		smsg, err = SignMsg(*msg, Globals.Zonename, sak)
		if err != nil {
			log.Printf("Error from SignMsgNG2(%s): %v", Globals.Zonename, err)
			return err
		}
	} else {
		fmt.Printf("Keyfile not specified, not signing message.\n")
	}

	rcode, err := SendUpdate(smsg, pzone, target.Addresses)
	if err != nil {
		log.Printf("Error from SendUpdate(%s): %v", target, err)
		return err
	} else {
		log.Printf("SendUpdate(parent=%s, target=%s) returned rcode %s", pzone, target, dns.RcodeToString[rcode])
	}
	return nil
}

// Note: the target.Addresses must already be in addr:port format.
// func SendUpdate(msg *dns.Msg, zonename string, target *DsyncTarget) (int, error) {
func SendUpdate(msg *dns.Msg, zonename string, addrs []string) (int, error) {
	if zonename == "." {
		log.Printf("Error: zone name not specified. Terminating.\n")
		return 0, fmt.Errorf("zone name not specified")
	}

	log.Printf("SendUpdate(%s) target has %d addresses: %v", zonename, len(addrs), addrs)

	for _, dst := range addrs {
		if Globals.Verbose {
			log.Printf("Sending DNS UPDATE for zone %s to %s\n", zonename, dst)
		}

		if Globals.Debug {
			log.Printf("Sending Update:\n%s\n", msg.String())
		}

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
	return 0, fmt.Errorf("Error: all target addresses %v responded with errors or were reachable", addrs)
}

// Parent is the zone to apply the update to.
// XXX: This is to focused on creating updates for child delegation info. Need a more general
// function that can create updates for other things too.
func CreateChildUpdate(parent, child string, adds, removes []dns.RR) (*dns.Msg, error) {
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

	// XXX: This logic is ok, but it should be in the caller, not here.
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

func CreateUpdate(zone string, adds, removes []dns.RR) (*dns.Msg, error) {
	if zone == "." || zone == "" {
		return nil, fmt.Errorf("CreateUpdate: Error: zone to update not specified. Terminating.")
	}

	m := new(dns.Msg)
	m.SetUpdate(zone)

	m.Remove(removes)
	m.Insert(adds)

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

// Find the best scheme (from the POV of the child) to sync the deletation with the parent
func (zd *ZoneData) BestSyncScheme() (string, *DsyncTarget, error) {
	var active_drr *DSYNC
	var active_scheme string
	var dsynctarget DsyncTarget

	zd.Logger.Printf("BestSyncScheme: imr=%s zone=%s", Globals.IMR, zd.ZoneName)

	// dsync_rrs, parent, err := DsyncDiscovery(zd.ZoneName, Globals.IMR, Globals.Verbose)
	dsync_res, err := DsyncDiscovery(zd.ZoneName, Globals.IMR, Globals.Verbose)
	if err != nil {
		zd.Logger.Printf("BestSyncScheme: Error from DsyncDiscovery(): %v", err)
		return "", nil, err
	}
	if len(dsync_res.Rdata) == 0 {
		msg := fmt.Sprintf("No DSYNC RRs for %s found in parent %s.", zd.ZoneName, dsync_res.Parent)
		zd.Logger.Printf("SyncWithParent: %s. Synching not possible.", msg)
		return "", nil, fmt.Errorf("Error: %s", msg)
	}
	schemes := viper.GetStringSlice("delegationsync.child.schemes")
	if len(schemes) == 0 {
		zd.Logger.Printf("BestSyncScheme: Error: no syncronization schemes configured for child %s", zd.ZoneName)
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
				if drr.Scheme == SchemeNotify && (drr.Type == dns.TypeCSYNC || drr.Type == dns.TypeANY) {
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

	zd.Logger.Printf("BestSyncScheme: zone %s (parent %s) DSYNC alternatives are:", zd.ZoneName, dsync_res.Parent)
	for _, drr := range dsync_res.Rdata {
		zd.Logger.Printf("%s\tIN\tDSYNC\t%s", dsync_res.Qname, drr.String())
	}

	tmp, err := net.LookupHost(active_drr.Target)
	if err != nil {
		return "", nil, fmt.Errorf("Error: %v", err)
	}
	for _, addr := range tmp {
		dsynctarget.Addresses = append(dsynctarget.Addresses, net.JoinHostPort(addr, fmt.Sprintf("%d", active_drr.Port)))
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
