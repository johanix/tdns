/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"time"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// This is only called from the CLI command "tdns-cli ddns sync" and uses a SIG(0) key from the
// command line rather than the one in the keystore. Not to be used by TDNS-SERVER.
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

// exchangeCancellable performs a DNS exchange that a cancelled context actually
// interrupts.
//
// client.ExchangeContext is not enough on its own, which is easy to miss: it
// passes the context to the dial and then uses only ctx.Deadline() to tighten
// the socket deadlines. It never watches ctx.Done(). A context that is
// cancellable but carries no deadline -- which is what a shutdown context is --
// therefore leaves a read in progress running to the client's own timeout,
// 2 seconds by default in this fork. Cancelling looked like it worked because
// the call did return; it returned on the timeout.
//
// Closing the connection is what actually stops it. The watcher goroutine exits
// on either branch, so nothing is left behind when the exchange completes
// normally, and the read error that a close produces is turned into the
// abandoned error by the ctx.Err() check at the call site.
func exchangeCancellable(ctx context.Context, client *dns.Client, msg *dns.Msg, dst string) (*dns.Msg, time.Duration, error) {
	conn, err := client.DialContext(ctx, dst)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			// Unblocks a read that has already begun; the exchange returns an
			// error on a closed connection, which the caller reads as abandoned.
			conn.Close()
		case <-finished:
		}
	}()

	return client.ExchangeWithConnContext(ctx, msg, conn)
}

// SendUpdate sends a DNS UPDATE to the first address that answers.
// Note: the addrs must already be in addr:port format.
//
// ctx bounds the whole attempt, not just the dial. The exchange goes through
// exchangeCancellable, which is what makes that true: ExchangeContext alone
// would not, since it never watches ctx.Done() and a cancellable-but-deadlineless
// context would leave a read running to the client's own timeout. A cancelled
// root context therefore abandons a request already on the wire, rather than
// the sync plan being able to stop between candidates but not during one --
// which is the half of a shutdown that actually takes time.
//
// A cancel is reported as such, wrapping context.Canceled, and never as a
// transport failure. The difference matters to walkSyncPlan: a failed transport
// means try the next one, an abandoned one means stop and say so.
//
// Return contract: the error reports a TRANSPORT-level failure — no address
// produced a DNS response at all (i/o timeout, no route to host, connection
// refused) — or an abandoned exchange. A response carrying a rejection RCODE is
// a successful exchange, so it is reported through the returned rcode with a NIL
// error; the caller decides what the rejection means.
//
// This matters because the whole delegation-sync RCODE policy of
// draft-ietf-dnsop-delegation-mgmt-via-ddns-02 (BADKEY -> re-bootstrap, REFUSED
// -> bounded retry; see sendUpdateWithRetry) keys on the rcode. An earlier
// version returned the rcode ONLY on the NOERROR path and folded every rejection
// into "all target addresses responded with errors", which made those branches
// unreachable: every BADKEY and REFUSED arrived as a transport error carrying
// rcode 0. ksk_rollover_ds_push.go already documented this contract and
// mis-categorised every parent rejection as SoftfailTransport because of it.
//
// Every caller must therefore check the rcode as well as the error; a nil error
// alone does NOT mean the parent applied the update.
func SendUpdate(ctx context.Context, msg *dns.Msg, zonename string, addrs []string) (int, UpdateResult, error) {
	if zonename == "." {
		lgDns.Error("SendUpdate: zone name not specified")
		return 0, UpdateResult{}, fmt.Errorf("zone name not specified")
	}

	lgDns.Info("SendUpdate", "zone", zonename, "numAddresses", len(addrs), "addresses", addrs)

	var ur = UpdateResult{
		TargetStatus: make(map[string]TargetUpdateStatus),
	}

	var edeFound bool
	var edeCode uint16
	var edeMessage string

	// Force TCP for these delegation-sync UPDATEs regardless of message
	// size. Per draft-ietf-dnsop-delegation-mgmt-via-ddns-02 §"Choice of
	// SIG(0) Signature Algorithm": these UPDATEs are infrequent and SHOULD
	// be carried over TCP (or a connection-oriented secure transport such
	// as DoT). TCP avoids the UDP spoofing/fragmentation exposure of a
	// message that mutates parent-side state, and accommodates the larger
	// SIG(0) signatures of post-quantum algorithms (e.g. ML-DSA-44, whose
	// signature alone is ~2.4 KB).
	//
	// Do NOT "optimize" this back to a size-gated UDP-first path: dns.Exchange
	// is hardcoded UDP and does not fall back on truncation, so a too-large
	// UPDATE would just time out — and the draft prefers TCP for all of these
	// UPDATEs regardless of size, not only the large ones.
	useTCP := true
	client := &dns.Client{Net: "tcp"}

	// The last rejection RCODE actually received from a responding address.
	// Tracked across the loop so that a non-NOERROR answer is still reported to
	// the caller after the remaining addresses have been tried: "try the next
	// address" must not cost us the rejection reason.
	var lastRcode int
	var gotResponse bool

	for _, dst := range addrs {
		lgDns.Debug("sending DNS UPDATE", "zone", zonename, "dst", dst,
			"net", map[bool]string{true: "tcp", false: "udp"}[useTCP],
			"size", msg.Len())

		lgDns.Debug("sending update message", "msg", msg.String())

		if cerr := ctx.Err(); cerr != nil {
			return 0, UpdateResult{}, fmt.Errorf("UPDATE to %s abandoned: %w", zonename, cerr)
		}
		res, _, err := exchangeCancellable(ctx, client, msg, dst)
		if err != nil {
			// A cancel DURING the exchange arrives here as an ordinary error,
			// and must not be filed as one. Falling through would record a
			// fabricated per-target failure and, with a single address -- the
			// usual DSYNC target -- end the loop and return "all target
			// addresses responded with errors or were unreachable". walkSyncPlan
			// then reports that every available scheme failed, which is exactly
			// the diagnosis the plan's own comments say a shutdown must not
			// produce: the remaining transports were never tried, they were
			// abandoned.
			//
			// The pre-loop check above only catches a cancel BETWEEN addresses.
			// This is the one the exchange was made context-aware for.
			if cerr := ctx.Err(); cerr != nil {
				return 0, ur, fmt.Errorf("UPDATE to %s abandoned mid-exchange with %s: %w",
					zonename, dst, cerr)
			}
			lgDns.Warn("error from dns.Exchange, trying next address", "dst", dst, "err", err)
			ur.TargetStatus[dst] = TargetUpdateStatus{
				Error:      true,
				ErrorMsg:   err.Error(),
				EDEFound:   false,
				EDEMessage: edeMessage,
				Sender:     dst,
			}
			if res != nil {
				lgDns.Debug("partial response", "msg", res.String())
			}
			continue
		}

		edeFound, edeCode, edeMessage = edns0.ExtractEDEFromMsg(res)
		lgDns.Debug("ExtractEDEFromMsg result", "edeFound", edeFound, "edeCode", edeCode, "edeMessage", edeMessage)
		edeSender := ""
		if edeFound {
			edeSender = dst
			lgDns.Info("EDE found in response", "edeCode", edeCode, "edeMessage", edeMessage)
		}
		ur.TargetStatus[dst] = TargetUpdateStatus{
			Rcode:      res.Rcode,
			EDEFound:   edeFound,
			EDECode:    edeCode,
			EDEMessage: edeMessage,
			Sender:     edeSender,
		}

		lastRcode, gotResponse = res.Rcode, true

		if res.Rcode != dns.RcodeSuccess {
			lgDns.Debug("got bad rcode", "rcode", dns.RcodeToString[res.Rcode], "response", res.String())
			lgDns.Warn("error rcode from target, trying next address", "dst", dst, "rcode", dns.RcodeToString[res.Rcode])
			continue
		} else {
			lgDns.Debug("got rcode NOERROR", "response", res.String())
			return res.Rcode, ur, nil
		}
	}

	// At least one address answered, but none with NOERROR. That is a parent
	// REJECTION, not a transport failure: hand the caller the rcode (and a nil
	// error) so it can apply the draft's per-RCODE policy.
	if gotResponse {
		lgDns.Warn("all target addresses rejected the update", "zone", zonename,
			"addresses", addrs, "rcode", dns.RcodeToString[lastRcode])
		return lastRcode, ur, nil
	}

	// No address produced a DNS response at all — a genuine transport failure.
	return 0, ur, fmt.Errorf("all target addresses %v were unreachable", addrs)
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
			// In-bailiwick means inside the child zone as a DNS NAME. A byte
			// suffix calls ns1.evilchild.example. in-bailiwick for
			// child.example., so glue for an unrelated delegation was deleted
			// alongside this one -- and it missed in-bailiwick glue whose case
			// differed from the child name's.
			if dns.IsSubDomain(child, ns.Ns) {
				rrA := new(dns.A)
				rrA.Hdr = dns.RR_Header{Name: ns.Ns, Rrtype: dns.TypeA, Class: dns.ClassANY, Ttl: 3600}
				rrAAAA := new(dns.AAAA)
				rrAAAA.Hdr = dns.RR_Header{Name: ns.Ns, Rrtype: dns.TypeAAAA, Class: dns.ClassANY, Ttl: 3600}
				m.RemoveRRset([]dns.RR{rrA, rrAAAA})
			}
		}
	}

	m.SetEdns0(1232, true) // Enable EDNS0 for EDE support in responses

	lgDns.Debug("created child update msg", "parent", parent, "child", child, "msg", m.String())
	return m, nil
}

// CreateChildReplaceUpdate creates a DNS UPDATE message that replaces all delegation data
// CreateChildReplaceUpdate creates a DNS UPDATE message for parent that replaces the delegation for child.
// It removes all existing NS records for the child and deletes A/AAAA glue for any in-bailiwick nameservers
// discovered among the provided new NS, A, and AAAA records, then inserts the new NS and glue RRs.
// Returns an error if parent or child is empty or equal to ".".
// CreateChildReplaceUpdate builds a replace-mode update that says nothing about
// DS unless newDS is non-empty.
//
// That rule is right for callers whose newDS is only populated in some cases:
// an empty slice there means "this caller has no DS opinion", and deleting the
// parent's DS RRset on the strength of it would remove a DS on the basis of a
// field nobody filled in. Callers that can tell the difference should use
// CreateChildReplaceUpdateWithDS and say so explicitly.
func CreateChildReplaceUpdate(parent, child string, newNS, newA, newAAAA, newDS []dns.RR) (*dns.Msg, error) {
	return CreateChildReplaceUpdateWithDS(parent, child, newNS, newA, newAAAA, newDS, len(newDS) > 0)
}

// CreateChildReplaceUpdateWithDS is CreateChildReplaceUpdate with the DS
// question answered explicitly.
//
// dsKnown says whether newDS is an answer. When it is, an empty newDS deletes
// the parent's DS RRset and adds nothing back -- the correct outcome for a zone
// that is no longer signed, where leaving the DS makes every validating
// resolver declare the whole child bogus. When it is not, the DS RRset is left
// untouched no matter what newDS holds.
//
// The distinction cannot be recovered from the slice. An empty DS set is the
// same nil either way, and which of the two it means depends on who filled it
// in, so the answer is a parameter rather than an inference.
func CreateChildReplaceUpdateWithDS(parent, child string, newNS, newA, newAAAA, newDS []dns.RR, dsKnown bool) (*dns.Msg, error) {
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
			if dns.IsSubDomain(child, ns.Ns) {
				nsNames[ns.Ns] = true
			}
		}
	}
	// Also check for any glue records being added (they might be for NS not yet in newNS)
	for _, arr := range newA {
		if dns.IsSubDomain(child, arr.Header().Name) {
			nsNames[arr.Header().Name] = true
		}
	}
	for _, aaaarr := range newAAAA {
		if dns.IsSubDomain(child, aaaarr.Header().Name) {
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

	// Remove all existing DS records for the child zone, but only when the
	// caller has actually answered the DS question. See the doc comments above:
	// an empty newDS from a caller that cannot tell "unsigned" from "no
	// opinion" must not delete anything.
	if dsKnown {
		rrDS := new(dns.DS)
		rrDS.Hdr = dns.RR_Header{Name: child, Rrtype: dns.TypeDS, Class: dns.ClassANY, Ttl: 3600}
		m.RemoveRRset([]dns.RR{rrDS})
	}

	// Add all new NS records
	m.Insert(newNS)

	// Add all new glue records
	m.Insert(newA)
	m.Insert(newAAAA)

	// Add all new DS records -- under the same gate as the removal above. A
	// caller with no DS opinion must produce a message that says nothing about
	// DS at all; inserting while declining to remove would leave the parent
	// holding both the old records and the new ones.
	if dsKnown {
		m.Insert(newDS)
	}

	m.SetEdns0(1232, true) // Enable EDNS0 for EDE support in responses

	lgDns.Debug("created replace update msg", "parent", parent, "child", child, "msg", m.String())
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

	lgDns.Debug("created update msg", "zone", zone, "msg", m.String())
	return m, nil
}

// Only used in the CLI version
func ComputeRRDiff(childpri, parpri, owner string, rrtype uint16) (bool, []dns.RR, []dns.RR, error) {
	if Globals.Debug {
		//	fmt.Printf("*** ComputeRRDiff(%s, %s)\n", owner, dns.TypeToString[rrtype])
		fmt.Printf("*** ComputeRRDiff(%s, %s, %s, %s)\n", childpri, parpri, owner, dns.TypeToString[rrtype])
	}
	rrname := dns.TypeToString[rrtype]
	rrs_parent, err := AuthQuery(owner, parpri, rrtype)
	if err != nil {
		return false, nil, nil, fmt.Errorf("looking up child %s RRset in parent primary %s: %w", rrname, parpri, err)
	}

	rrs_child, err := AuthQuery(owner, childpri, rrtype)
	if err != nil {
		return false, nil, nil, fmt.Errorf("looking up child %s RRset in child primary %s: %w", rrname, childpri, err)
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
	return differ, adds, removes, nil
}

// XXX: Should be replaced by four calls: one per child and parent primary to get
//
//	the NS RRsets and one to new ComputeBailiwickNS() that takes a []dns.RR + zone name
func ComputeBailiwickNS(childpri, parpri, owner string) ([]string, []string, error) {
	ns_parent, err := AuthQuery(owner, parpri, dns.TypeNS)
	if err != nil {
		return nil, nil, fmt.Errorf("looking up child NS RRset in parent primary %s: %w", parpri, err)
	}

	ns_child, err := AuthQuery(Globals.Zonename, childpri, dns.TypeNS)
	if err != nil {
		return nil, nil, fmt.Errorf("looking up child NS RRset in child primary %s: %w", childpri, err)
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
	return child_inb, parent_inb, nil
}

// Return the names of NS RRs that are in bailiwick for the zone.
func BailiwickNS(zonename string, nsrrs []dns.RR) ([]string, error) {
	var ns_inbailiwick []string
	for _, rr := range nsrrs {
		if ns, ok := rr.(*dns.NS); ok {
			// Compared on LABEL boundaries: a bare strings.HasSuffix accepts
			// "ns.notexample.com." as in-bailiwick for "example.com.", because
			// the suffix matches across a label boundary. That name is in a
			// different zone entirely, so treating it as in-bailiwick means
			// looking for glue where none can exist.
			//
			// dns.IsSubDomain compares whole labels, and is case-insensitive as
			// DNS requires -- the old comparison also missed "NS.EXAMPLE.COM."
			// for the same zone.
			if dns.IsSubDomain(dns.Fqdn(zonename), dns.Fqdn(ns.Ns)) {
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
			if dns.IsSubDomain(owner, ns.Ns) {
				old_ns_inb = append(old_ns_inb, ns.Ns)
			}
		}
	}
	for _, rr := range newnsrrset {
		if ns, ok := rr.(*dns.NS); ok {
			if dns.IsSubDomain(owner, ns.Ns) {
				new_ns_inb = append(new_ns_inb, ns.Ns)
			}
		}
	}

	return new_ns_inb, old_ns_inb
}
*/
