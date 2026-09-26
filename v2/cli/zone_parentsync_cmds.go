/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

// newZoneParentSyncCmd returns a fresh "parentsync" subtree for the child role.
func newZoneParentSyncCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "parentsync",
		Short: "Child-side parent delegation sync commands",
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Show whether a delegation change can reach the parent, and by which scheme",
		Long: `For a zone with parentsync (a zone syncing its own delegation) or
parentsync-proxy (a tdns-agent secondary syncing on behalf of its primary),
report whether a delegation change can reach the parent right now, by which
scheme, and if not, why not:

  - the parent, and whether its DSYNC RRset validated;
  - every scheme in parentsync.schemes, in preference order: usable (with
    its target) or skipped (with the reason);
  - detail for the configured schemes: for UPDATE on a parentsync-proxy zone
    the KEY-bootstrap state and the records to publish at the primary (what
    "zone proxy-key" used to print), for UPDATE on a parentsync zone its
    SIG(0) key and what the parent holds for it, for NOTIFY whether the zone
    publishes CDS and CSYNC, for API whether a credential is configured;
  - whether the parent's delegation is in sync with the zone, as
    "parentsync delta" computes it, and the zone's delegation-sync-warning.

Nothing on the zone is changed, with one exception: on a parentsync-proxy zone
waiting for its KEY to be published, the agent's SIG(0) keypair is generated
if it has none -- as the agent's next sync would -- so that there are records
to print.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			showParentSyncStatus(api, "Error from server")
		},
	}

	var bootstrapScheme string
	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap the SIG(0) key with the parent",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
				Command: "bootstrap",
				Zone:    dns.Fqdn(tdns.Globals.Zonename),
				Scheme:  bootstrapScheme,
			})
			PrintUpdateResult(resp.UpdateResult)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				os.Exit(1)
			}
			if resp.Error {
				fmt.Printf("Error from server: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}
			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
	// Only "update" is implemented; it negotiates the actual method with the
	// parent from the advertised and willing lists. Defaulted rather than
	// required, so the working case needs no flag at all.
	bootstrap.Flags().StringVar(&bootstrapScheme, "scheme", "update", "Bootstrap scheme (only \"update\" is implemented)")

	rollKey := &cobra.Command{
		Use:   "roll-key",
		Short: "Roll the SIG(0) key with the parent",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename", "rollaction")
			alg := ResolveAlgorithm(role, useSIG0)
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
				Command:   "roll-key",
				Zone:      dns.Fqdn(tdns.Globals.Zonename),
				Algorithm: alg,
				Action:    rollaction,
			})
			PrintUpdateResult(resp.UpdateResult)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				os.Exit(1)
			}
			if resp.Error {
				fmt.Printf("Error from server: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}
			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
	rollKey.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "",
		sig0AlgorithmsHelp("Algorithm for the new SIG(0) key"))
	rollKey.PersistentFlags().StringVarP(&rollaction, "rollaction", "r", "complete", "[debug] Phase of the rollover to perform: complete, add, remove, update-local")
	rollKey.PersistentFlags().MarkHidden("rollaction")

	inquireRun := func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		api, err := GetApiClient(role, true)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
			Command: "inquire",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from server: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}
		fmt.Printf("KeyState Inquiry for %s\n", dns.Fqdn(tdns.Globals.Zonename))
		fmt.Printf("  KeyID:        %d\n", resp.KeyID)
		fmt.Printf("  Parent says:  %s (code %d)\n", resp.StateName, resp.KeyState)
		fmt.Printf("  Authenticated: %v\n", resp.Authenticated)
	}

	inquire := &cobra.Command{
		Use:   "inquire",
		Short: "Inquire the parent about the current SIG(0) key state",
		Run:   inquireRun,
	}
	// The retired agent subtree spelled this "inquire update", with "inquire"
	// as a bare prefix. Kept as a hidden child so that spelling still runs,
	// rather than failing with "unknown command" for anyone who has it in a
	// script.
	inquire.AddCommand(&cobra.Command{
		Use:    "update",
		Short:  "Deprecated spelling of \"parentsync inquire\"",
		Hidden: true,
		Run:    inquireRun,
	})

	delta := &cobra.Command{
		Use:   "delta",
		Short: "Compute delta between parent delegation data and child zone data",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}
			dr, err := SendDelegationCmd(api, tdns.DelegationPost{
				Command: "status",
				Zone:    tdns.Globals.Zonename,
			})
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			if dr.Error {
				fmt.Printf("Error: %s\n", dr.ErrorMsg)
				os.Exit(1)
			}
			fmt.Printf("%s\n", dr.Msg)
			printDelegationDelta(os.Stdout, dr.SyncStatus)
		},
	}

	sync := &cobra.Command{
		Use:   "sync",
		Short: "Sync delegation data in parent zone via DDNS UPDATE",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}
			dr, err := SendDelegationCmd(api, tdns.DelegationPost{
				Command: "sync",
				Zone:    tdns.Globals.Zonename,
			})
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			if dr.Error {
				fmt.Printf("Error: %s\n", dr.ErrorMsg)
				os.Exit(1)
			}
			fmt.Printf("%s\n", dr.Msg)
		},
	}

	c.AddCommand(status, bootstrap, rollKey, inquire, delta, sync)
	return c
}

// showParentSyncStatus asks the daemon for the parentsync status of
// tdns.Globals.Zonename and prints it. Shared by "zone parentsync status" and
// the hidden "zone dsync status" aliases, so the old spellings print the same
// report rather than the table the report replaced. errPrefix names who
// answered, as each caller always has.
func showParentSyncStatus(api *tdns.ApiClient, errPrefix string) {
	resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
		Command: "status",
		Zone:    dns.Fqdn(tdns.Globals.Zonename),
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	if resp.Error {
		fmt.Printf("%s: %s\n", errPrefix, resp.ErrorMsg)
		os.Exit(1)
	}
	if resp.Report == nil {
		// A daemon from before the report: its Functions table.
		printParentSyncStatus(resp)
		return
	}
	printParentSyncReport(os.Stdout, resp.Zone, resp.Report, resp.Todo)
}

// printDelegationDelta renders a parent-vs-zone comparison: the verdict, and
// when out of sync the changes the parent needs. Shared by "parentsync delta",
// "ddns del status" and "parentsync status", which all read the same
// DELEGATION-STATUS answer.
func printDelegationDelta(w io.Writer, dss tdns.DelegationSyncStatus) {
	if dss.InSync {
		fmt.Fprintf(w, "Delegation information in parent %s is in sync with child %s. No action needed.\n",
			dss.Parent, dss.ZoneName)
		return
	}
	fmt.Fprintf(w, "Delegation information in parent %q is NOT in sync with child %q. Changes needed:\n",
		dss.Parent, dss.ZoneName)
	fmt.Fprintf(w, "%s\n", columnize.SimpleFormat(delegationChangeRows(dss)))
}

// delegationChangeRows is the change table, header first. DS is included: the
// comparison has always computed it, and the table used to drop it.
func delegationChangeRows(dss tdns.DelegationSyncStatus) []string {
	out := []string{"Change|RR"}
	add := func(label string, rrs []string) {
		for _, rr := range rrs {
			out = append(out, fmt.Sprintf("%s|%s", label, rr))
		}
	}
	add("ADD NS", dss.NsAddsStr)
	add("DEL NS", dss.NsRemovesStr)
	add("ADD IPv4 GLUE", dss.AAddsStr)
	add("DEL IPv4 GLUE", dss.ARemovesStr)
	add("ADD IPv6 GLUE", dss.AAAAAddsStr)
	add("DEL IPv6 GLUE", dss.AAAARemovesStr)
	add("ADD DS", dss.DSAddsStr)
	add("DEL DS", dss.DSRemovesStr)
	return out
}

// printParentSyncReport renders the "status" report (#790), one section per
// question, blank lines between them:
//
//	the parent and the schemes in preference order
//	the detail for each configured scheme that has any
//	the delegation: in sync with the parent, or the changes it needs
//	the zone's delegation-sync-warning, and any TODO
func printParentSyncReport(w io.Writer, zone string, r *tdns.ParentSyncReport, todo []string) {
	var sections []string

	var b strings.Builder
	parent := r.Parent
	if parent == "" {
		parent = "(unknown)"
	}
	fmt.Fprintf(&b, "Zone %s (%s): parent %s", zone, r.Role, parent)
	switch {
	case r.PlanError != "":
		fmt.Fprintf(&b, "; DSYNC discovery failed: %s\n", r.PlanError)
	case r.PlanNote != "":
		fmt.Fprintf(&b, "\nSchemes: none evaluated: %s\n", r.PlanNote)
	default:
		if r.Validated {
			b.WriteString(", DSYNC validated\n")
		} else {
			b.WriteString(", DSYNC NOT validated\n")
		}
		b.WriteString("Schemes (in preference order):\n")
		width := 0
		for _, s := range r.Schemes {
			width = max(width, len(s.Scheme))
		}
		for _, s := range r.Schemes {
			if s.Usable {
				fmt.Fprintf(&b, "  %-*s  %-8s %s\n", width, s.Scheme, "usable:", s.Target)
			} else {
				fmt.Fprintf(&b, "  %-*s  %-8s %s\n", width, s.Scheme, "skipped:", s.Reason)
			}
		}
	}
	sections = append(sections, b.String())

	if u := r.Update; u != nil {
		if u.ProxyReport != "" {
			// Word for word what "zone proxy-key" prints.
			sections = append(sections, u.ProxyReport)
		} else if r.Role != "parentsync-proxy" {
			sections = append(sections, childUpdateSection(u))
		}
	}

	var other []string
	if n := r.Notify; n != nil {
		signed := "signed"
		if !n.Signed {
			signed = "unsigned"
		}
		other = append(other, fmt.Sprintf("NOTIFY: the zone is %s; it publishes CDS: %s, CSYNC: %s",
			signed, yesNo(n.PublishesCDS), yesNo(n.PublishesCSYNC)))
	}
	if a := r.Api; a != nil {
		line := fmt.Sprintf("API: a usable credential for parent %s is configured", parent)
		if !a.CredentialConfigured {
			line = fmt.Sprintf("API: no usable credential for parent %s (parentsync.api.credentials)", parent)
		}
		if a.AllowInsecure {
			line += "; parentsync.api.allow-insecure is set"
		}
		other = append(other, line)
	}
	if len(other) > 0 {
		sections = append(sections, strings.Join(other, "\n")+"\n")
	}

	b.Reset()
	if r.Delegation != nil {
		printDelegationDelta(&b, *r.Delegation)
	} else {
		fmt.Fprintf(&b, "Delegation: could not compare with the parent: %s\n", r.DelegationError)
	}
	sections = append(sections, b.String())

	if r.Warning != "" {
		sections = append(sections, fmt.Sprintf("Warning (delegation-sync-warning): %s\n", r.Warning))
	}
	if len(todo) > 0 {
		b.Reset()
		b.WriteString("TODO:\n")
		for _, t := range todo {
			fmt.Fprintf(&b, "--> %s\n", t)
		}
		sections = append(sections, b.String())
	}

	fmt.Fprint(w, strings.Join(sections, "\n"))
}

// childUpdateSection is the UPDATE detail for a zone syncing its own
// delegation: its SIG(0) key, whether the KEY is at the apex, and what the
// parent holds for it.
func childUpdateSection(u *tdns.ParentSyncUpdateReport) string {
	var b strings.Builder
	if !u.HaveActiveKey {
		b.WriteString("UPDATE: the zone has no active SIG(0) key\n")
	} else {
		published := false
		for _, id := range u.ApexKeyIDs {
			if id == u.ActiveKeyID {
				published = true
			}
		}
		switch {
		case published:
			fmt.Fprintf(&b, "UPDATE: SIG(0) key %d is active and its KEY is published at the apex\n", u.ActiveKeyID)
		case len(u.ApexKeyIDs) == 0:
			fmt.Fprintf(&b, "UPDATE: SIG(0) key %d is active; the apex has no KEY\n", u.ActiveKeyID)
		default:
			fmt.Fprintf(&b, "UPDATE: SIG(0) key %d is active; the apex has KEY %v, not this one\n",
				u.ActiveKeyID, u.ApexKeyIDs)
		}
	}
	if u.ParentKeyError != "" {
		fmt.Fprintf(&b, "UPDATE: the parent's view of the key: %s\n", u.ParentKeyError)
	} else {
		auth := "authenticated"
		if !u.ParentKeyAuthenticated {
			auth = "NOT authenticated"
		}
		fmt.Fprintf(&b, "UPDATE: the parent's view of key %d: %s (%s)\n", u.ActiveKeyID, u.ParentKeyState, auth)
	}
	return b.String()
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// printParentSyncStatus renders the Msg, Functions, and Todo from a
// /zone/parentsync status response from a daemon that predates the report.
func printParentSyncStatus(resp tdns.ZoneParentSyncResponse) {
	if resp.Msg != "" {
		fmt.Printf("%s\n", resp.Msg)
	}
	out := []string{}
	for key, s := range resp.Functions {
		out = append(out, fmt.Sprintf("%s|%s", key, s))
	}
	sort.Strings(out)
	if tdns.Globals.ShowHeaders {
		out = append([]string{"Function|Status"}, out...)
	}
	fmt.Printf("%s\n", columnize.SimpleFormat(out))
	if len(resp.Todo) > 0 {
		fmt.Printf("\nTODO:\n")
		for _, todo := range resp.Todo {
			fmt.Printf("--> %s\n", todo)
		}
	}
}

// SendParentSyncCommand POSTs a ZoneParentSyncPost to /zone/parentsync.
func SendParentSyncCommand(api *tdns.ApiClient, data tdns.ZoneParentSyncPost) (tdns.ZoneParentSyncResponse, error) {
	var cr tdns.ZoneParentSyncResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/zone/parentsync", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return cr, fmt.Errorf("error from api post: %v", err)
	}
	if status != 200 && tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("error from unmarshal: %v", err)
	}
	// cr.Error is NOT turned into a Go error: the callers render it
	// themselves ("Error from server: ..."), and wrapping it here made that
	// branch unreachable and doubled the prefix on the path that did run.
	// A non-nil error from this function means the exchange failed.
	return cr, nil
}
