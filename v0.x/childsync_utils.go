/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	core "github.com/johanix/tdns/v0.x/core"
	edns0 "github.com/johanix/tdns/v0.x/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// This is only called from the CLI command "tdns-cli ddns sync" and uses a SIG(0) key from the
// command line rather than the one in the keystore. Not to be used by TDNS-SERVER.
func xxxChildSendDdnsSync(pzone string, target *DsyncTarget, adds, removes []dns.RR) (UpdateResult, error) {
	msg, err := CreateChildUpdate(pzone, Globals.Zonename, adds, removes)
	if err != nil {
		return UpdateResult{}, fmt.Errorf("error from CreateChildUpdate(%s): %v", pzone, err)
	}

	pkc, err := LoadSig0SigningKey(Globals.Sig0Keyfile)
	if err != nil {
		log.Printf("Error from LoadSig0SigningKeyNG(%s): %v", Globals.Sig0Keyfile, err)
		return UpdateResult{}, fmt.Errorf("error from LoadSig0SigningKeyNG(%s): %v", Globals.Sig0Keyfile, err)
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
			return UpdateResult{}, fmt.Errorf("error from SignMsg(%s): %v", Globals.Zonename, err)
		}
	} else {
		fmt.Printf("Keyfile not specified, not signing message.\n")
	}

	rcode, ur, err := SendUpdate(smsg, pzone, target.Addresses)
	if err != nil {
		log.Printf("Error from SendUpdate(%s): %v", target.Name, err)
		return ur, err
	} else {
		log.Printf("SendUpdate(parent=%s, target=%s) returned rcode %s", pzone, target.Name, dns.RcodeToString[rcode])
	}
	return ur, nil
}

type UpdateResult struct {
	EDEFound     bool
	EDECode      uint16
	EDEMessage   string
	EDESender    string
	Rcode        int
	TargetStatus map[string]TargetUpdateStatus
}

type TargetUpdateStatus struct {
	Sender     string
	Rcode      int
	Error      bool
	ErrorMsg   string
	EDEFound   bool
	EDECode    uint16
	EDEMessage string
}

// Note: the target.Addresses must already be in addr:port format.
// func SendUpdate(msg *dns.Msg, zonename string, target *DsyncTarget) (int, error) {
// func SendUpdate(msg *dns.Msg, zonename string, addrs []string) (int, error, UpdateResult) {
func SendUpdate(msg *dns.Msg, zonename string, addrs []string) (int, UpdateResult, error) {
	if zonename == "." {
		log.Printf("Error: zone name not specified. Terminating.\n")
		return 0, UpdateResult{}, fmt.Errorf("zone name not specified")
	}

	log.Printf("SendUpdate(%s) target has %d addresses: %v", zonename, len(addrs), addrs)

	var ur = UpdateResult{
		TargetStatus: make(map[string]TargetUpdateStatus),
	}

	var edeFound bool
	var edeCode uint16
	var edeMessage string

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
			ur.TargetStatus[dst] = TargetUpdateStatus{
				Error:      true,
				ErrorMsg:   err.Error(),
				EDEFound:   false,
				EDEMessage: edeMessage,
				Sender:     dst,
			}
			log.Printf("Error msg: %s", res.String())
			if res != nil {
				log.Printf("Partial response: %s", res.String())
			}
			continue
		}

		edeFound, edeCode, edeMessage = edns0.ExtractEDEFromMsg(res)
		log.Printf("after ExtractEDEFromMsg: EDE found: %t, code: %d, message: %s", edeFound, edeCode, edeMessage)
		edeSender := ""
		if edeFound {
			edeSender = dst
			log.Printf("EDE Code: %d, EDE Message: %s", edeCode, edeMessage)
		}
		ur.TargetStatus[dst] = TargetUpdateStatus{
			Rcode:      res.Rcode,
			EDEFound:   edeFound,
			EDECode:    edeCode,
			EDEMessage: edeMessage,
			Sender:     edeSender,
		}

		if res.Rcode != dns.RcodeSuccess {
			if Globals.Verbose {
				log.Printf("... and got rcode %s back (bad)\n", dns.RcodeToString[res.Rcode])
				log.Printf("Response:\n%s\n", res.String())
			}
			log.Printf("Error from %s: Rcode: %s. Trying next address", dst, dns.RcodeToString[res.Rcode])
			continue
		} else {
			if Globals.Verbose {
				log.Printf("... and got rcode NOERROR back (good)\n")
				log.Printf("Response:\n%s\n", res.String())
			}
			return res.Rcode, ur, nil
		}
	}

	return 0, ur, fmt.Errorf("all target addresses %v responded with errors or were unreachable", addrs)
}

// Parent is the zone to apply the update to.
// XXX: This is to focused on creating updates for child delegation info. Need a more general
// CreateChildUpdate constructs a DNS UPDATE message for the given parent zone that applies the provided additions and removals for a child delegation.
//
// If any removed RR is an NS whose target name is within the child zone, the function also removes A and AAAA glue RRsets for that NS name.
// It validates that parent and child are non-empty and not ".", returning an error when validation fails.
// When Globals.Debug is set, the resulting message is printed.
//
// It returns the constructed DNS UPDATE message, or an error if validation fails.
func CreateChildUpdate(parent, child string, adds, removes []dns.RR) (*dns.Msg, error) {
	if parent == "." || parent == "" {
		return nil, fmt.Errorf("parent zone name not specified. Terminating")
	}
	if child == "." || child == "" {
		return nil, fmt.Errorf("child zone name not specified. Terminating")
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

// CreateChildReplaceUpdate creates a DNS UPDATE message that replaces all delegation data
// CreateChildReplaceUpdate creates a DNS UPDATE message for parent that replaces the delegation for child.
// It removes all existing NS records for the child and deletes A/AAAA glue for any in-bailiwick nameservers
// discovered among the provided new NS, A, and AAAA records, then inserts the new NS and glue RRs.
// Returns an error if parent or child is empty or equal to ".".
func CreateChildReplaceUpdate(parent, child string, newNS, newA, newAAAA []dns.RR) (*dns.Msg, error) {
	if parent == "." || parent == "" {
		return nil, fmt.Errorf("parent zone name not specified. Terminating")
	}
	if child == "." || child == "" {
		return nil, fmt.Errorf("child zone name not specified. Terminating")
	}

	m := new(dns.Msg)
	m.SetUpdate(parent)

	// Remove all existing NS records for the child zone
	rrNS := new(dns.NS)
	rrNS.Hdr = dns.RR_Header{Name: child, Rrtype: dns.TypeNS, Class: dns.ClassANY, Ttl: 3600}
	m.RemoveRRset([]dns.RR{rrNS})

	// Remove all existing glue records for in-bailiwick nameservers
	// We need to remove glue for all NS names that might have glue
	nsNames := make(map[string]bool)
	for _, nsrr := range newNS {
		if ns, ok := nsrr.(*dns.NS); ok {
			if strings.HasSuffix(ns.Ns, child) {
				nsNames[ns.Ns] = true
			}
		}
	}
	// Also check for any glue records being added (they might be for NS not yet in newNS)
	for _, arr := range newA {
		if strings.HasSuffix(arr.Header().Name, child) {
			nsNames[arr.Header().Name] = true
		}
	}
	for _, aaaarr := range newAAAA {
		if strings.HasSuffix(aaaarr.Header().Name, child) {
			nsNames[aaaarr.Header().Name] = true
		}
	}

	// Remove all A and AAAA records for these nameservers
	for nsName := range nsNames {
		rrA := new(dns.A)
		rrA.Hdr = dns.RR_Header{Name: nsName, Rrtype: dns.TypeA, Class: dns.ClassANY, Ttl: 3600}
		rrAAAA := new(dns.AAAA)
		rrAAAA.Hdr = dns.RR_Header{Name: nsName, Rrtype: dns.TypeAAAA, Class: dns.ClassANY, Ttl: 3600}
		m.RemoveRRset([]dns.RR{rrA, rrAAAA})
	}

	// Add all new NS records
	m.Insert(newNS)

	// Add all new glue records
	m.Insert(newA)
	m.Insert(newAAAA)

	if Globals.Debug {
		fmt.Printf("Creating replace update msg:\n%s\n", m.String())
	}
	return m, nil
}

// CreateUpdate creates a DNS UPDATE message for the given zone, applies the provided
// removals and additions, and enables EDNS0 (payload 1232 with the DO bit set) so
// that EDNS0 Extended DNS Error (EDE) information can be returned.
// It returns the constructed *dns.Msg, or an error if the zone is empty or ".".
func CreateUpdate(zone string, adds, removes []dns.RR) (*dns.Msg, error) {
	if zone == "." || zone == "" {
		return nil, fmt.Errorf("CreateUpdate: Error: zone to update not specified. Terminating")
	}

	m := new(dns.Msg)
	m.SetUpdate(zone)

	m.Remove(removes)
	m.Insert(adds)

	m.SetEdns0(1232, true) // UPDsize + DO-bit, the important thing is to have an OPT RR, to enable the return of EDE.

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

	differ, adds, removes := core.RRsetDiffer(owner, rrs_child, rrs_parent, rrtype, log.Default(), Globals.Verbose, Globals.Debug)
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

/*
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
*/

// Find the best scheme (from the POV of the child) to sync the deletation with the parent
func (zd *ZoneData) BestSyncScheme(ctx context.Context, imr *Imr) (string, *DsyncTarget, error) {
	var active_drr *core.DSYNC
	var active_scheme string
	var dsynctarget DsyncTarget

	zd.Logger.Printf("BestSyncScheme: zone=%s", zd.ZoneName)

	// dsync_rrs, parent, err := DsyncDiscovery(zd.ZoneName, Globals.IMR, Globals.Verbose)
	dsync_res, err := imr.DsyncDiscovery(ctx, zd.ZoneName, Globals.Verbose)
	if err != nil {
		zd.Logger.Printf("BestSyncScheme: Error from DsyncDiscovery(): %v", err)
		return "", nil, err
	}
	if len(dsync_res.Rdata) == 0 {
		msg := fmt.Sprintf("No DSYNC RRs for %s found in parent %s.", zd.ZoneName, dsync_res.Parent)
		zd.Logger.Printf("SyncWithParent: %s. Synching not possible.", msg)
		return "", nil, fmt.Errorf("error: %s", msg)
	}
	schemes := viper.GetStringSlice("delegationsync.child.schemes")
	if len(schemes) == 0 {
		zd.Logger.Printf("BestSyncScheme: Error: no syncronization schemes configured for child %s", zd.ZoneName)
		return "", nil, fmt.Errorf("no synchronizations schemes configured for child %s", zd.ZoneName)
	}

schemeLoop:
	for _, scheme := range schemes {
		scheme = strings.ToLower(scheme)

		switch scheme {
		case "update":
			log.Printf("BestSyncScheme(): checking UPDATE alternative:")
			for _, drr := range dsync_res.Rdata {
				if drr.Scheme == core.SchemeUpdate {
					active_drr = drr
					break
				}
			}
			if active_drr != nil {
				log.Printf("BestSyncSchemes: found working UPDATE config, happy with that.")
				active_scheme = "UPDATE"
				break schemeLoop
			}

		case "notify":
			if active_scheme != "" {
				break schemeLoop
			}
			log.Printf("BestSyncScheme(): checking NOTIFY alternative:")
			for _, drr := range dsync_res.Rdata {
				if drr.Scheme == core.SchemeNotify && (drr.Type == dns.TypeCSYNC || drr.Type == dns.TypeANY) {
					active_drr = drr
					break
				}
			}
			if active_drr != nil {
				active_scheme = "NOTIFY"
				break schemeLoop
			}

		default:
			msg := fmt.Sprintf("zone %s: error: unknown child scheme: %s", zd.ZoneName, scheme)
			zd.Logger.Print(msg)
			return "", nil, errors.New(msg)
		}
	}

	zd.Logger.Printf("BestSyncScheme: zone %s (parent %s) DSYNC alternatives are:", zd.ZoneName, dsync_res.Parent)
	for _, drr := range dsync_res.Rdata {
		zd.Logger.Printf("%s\tIN\tDSYNC\t%s", dsync_res.Qname, drr.String())
	}

	tmp, err := net.LookupHost(active_drr.Target)
	if err != nil {
		return "", nil, fmt.Errorf("error: %v", err)
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
