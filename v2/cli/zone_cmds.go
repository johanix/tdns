/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

// peerConfAddrsString joins the .Addr value of each PeerConf with commas,
// for compact display of notify peers in the zone listing.
func peerConfAddrsString(peers []tdns.PeerConf) string {
	addrs := make([]string, 0, len(peers))
	for _, p := range peers {
		addrs = append(addrs, p.Addr)
	}
	return strings.Join(addrs, ",")
}

// NewZoneCmd returns a fresh "zone" command tree bound to the given
// role. Additional subcommands may be attached via extras — used by
// tdns-mp to inject signer-specific mplist under the signer's tree.
func NewZoneCmd(role string, extras ...*cobra.Command) *cobra.Command {
	c := &cobra.Command{
		Use:   "zone",
		Short: "Prefix command, not usable by itself",
	}
	c.PersistentFlags().BoolVarP(&force, "force", "F", false, "force operation")

	list := &cobra.Command{
		Use:   "list",
		Short: "List configured zones",
		Run:   func(cmd *cobra.Command, args []string) { RunZoneList(role, args) },
	}
	list.Flags().BoolVarP(&showfile, "file", "f", false, "Show zone input file")
	list.Flags().BoolVarP(&shownotify, "notify", "N", false, "Show zone downstream notify addresses")
	list.Flags().BoolVarP(&showprimary, "primary", "P", false, "Show zone primary nameserver")

	desc := &cobra.Command{
		Use:   "desc",
		Short: "Describe a single zone in full, including DNSSEC applied-policy state and policy detail",
		Long: `Print a detailed, multi-line record for one zone: everything "zone list -v"
shows (type, store, options, primaries, notify, error/warning state, effective
DNSSEC policy and override info) plus two DNSSEC sections not otherwise visible
from the CLI:

  1. the last-applied policy record recorded in the keystore (applied policy
     name, source config|command, and when it was applied); and
  2. the currently-bound policy's detail — mode, KSK/ZSK (or CSK) algorithms,
     key lifetimes and RRSIG validity.

An unsigned zone or an unresolvable policy degrades gracefully rather than
failing. Does not change anything; read-only.`,
		Run: func(cmd *cobra.Command, args []string) { RunZoneDesc(role, args) },
	}
	desc.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to describe")
	desc.MarkFlagRequired("zone")

	reload := &cobra.Command{
		Use:   "reload",
		Short: "Request re-loading a zone",
		Run:   func(cmd *cobra.Command, args []string) { RunZoneReload(role, args) },
	}
	reload.Flags().BoolVarP(&showError, "error", "e", false, "wait for reload to complete and report any parse errors")
	reload.Flags().StringVar(&errorTimeout, "timeout", "10s", "how long to wait for reload when --error is set (e.g. 10s, 2m)")

	sign := &cobra.Command{
		Use:   "sign",
		Short: "Request signing of a zone (additive: cover gaps with active keys)",
		Run: func(cmd *cobra.Command, args []string) {
			runZoneSimpleCmd(role, "sign-zone")
		},
	}

	resign := &cobra.Command{
		Use:   "resign",
		Short: "Re-sign zone from scratch with currently-active keys (drops all existing RRSIGs)",
		Run: func(cmd *cobra.Command, args []string) {
			runZoneSimpleCmd(role, "resign-zone")
		},
	}

	write := &cobra.Command{
		Use:   "write",
		Short: "Write a zone to disk",
		Run:   func(cmd *cobra.Command, args []string) { RunZoneWrite(role, args) },
	}

	freeze := &cobra.Command{
		Use:   "freeze",
		Short: "Freeze a zone (i.e. stop accepting DDNS updates to the zone data)",
		Run: func(cmd *cobra.Command, args []string) {
			runZoneSimpleCmd(role, "freeze")
		},
	}

	thaw := &cobra.Command{
		Use:   "thaw",
		Short: "Thaw a zone (i.e. accept DDNS updates to the zone data again)",
		Run: func(cmd *cobra.Command, args []string) {
			runZoneSimpleCmd(role, "thaw")
		},
	}

	bump := &cobra.Command{
		Use:   "bump",
		Short: "Bump SOA serial and epoch (if any) in the daemon's version of the zone",
		Run:   func(cmd *cobra.Command, args []string) { RunZoneBump(role, args) },
	}

	var setPolicyName string
	setPolicy := &cobra.Command{
		Use:   "policy-set",
		Short: "Set a zone's DNSSEC policy at runtime (persists as an override, not in YAML)",
		Long: `Apply a DNSSEC policy to a zone in the running server. The change is stored
as a per-zone override in the keystore and survives restart, but does NOT
update the zone's dnssec_policy in the YAML config — update that separately
to make the new policy the permanent base. If the new policy uses different
key algorithms, the old keys are retired (their signatures kept until the
KeyStateWorker removes them) and new keys take over; the zone stays signed
throughout.`,
		Run: func(cmd *cobra.Command, args []string) {
			RunZoneSetPolicy(role, setPolicyName)
		},
	}
	setPolicy.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to set the DNSSEC policy for")
	setPolicy.Flags().StringVarP(&setPolicyName, "policy", "p", "", "DNSSEC policy name to apply")
	setPolicy.MarkFlagRequired("zone")
	setPolicy.MarkFlagRequired("policy")

	var policyResetConfirm bool
	policyReset := &cobra.Command{
		Use:   "policy-reset",
		Short: "Reset a zone's DNSSEC keys to its config policy, per role (dry-run without --confirm)",
		Long: `Force a zone onto its config dnssec_policy: for each key role whose algorithm no
longer matches config, drop and regenerate that role's keys and re-sign; any
role whose algorithm is already correct is kept. It also clears the runtime
override and records the config policy as applied.

This is a break-glass tool for test/lab zones. It exists because an abrupt
policy switch that changes a KSK/ZSK algorithm is otherwise refused (that needs
a key rollover that is not built). If the KSK algorithm changes it BREAKS THE
CHAIN OF TRUST: the parent DS will not match the new KSK until you re-publish it
(a ZSK-only change keeps the KSK and the DS). NOT for production.

Run WITHOUT --confirm for a DRY RUN that previews what it would do (which roles
would roll, whether the parent DS would break) and changes nothing; add
--confirm to apply. A single --zone only (no wildcards, no bulk).`,
		Run: func(cmd *cobra.Command, args []string) {
			RunZoneResetPolicy(role, policyResetConfirm)
		},
	}
	policyReset.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to reset the DNSSEC policy for")
	policyReset.Flags().BoolVar(&policyResetConfirm, "confirm", false, "Apply the reset; without it the command is a dry-run that only previews what would happen")
	policyReset.MarkFlagRequired("zone")

	proxyKey := &cobra.Command{
		Use:   "proxy-key",
		Short: "Show the delegation-sync-proxy UPDATE state and the KEY to publish at the primary",
		Long: `For a zone with the delegation-sync-proxy option (a tdns-agent acting as a
secondary for a DSYNC-unaware primary), report whether the agent can proxy
DNS UPDATEs to the parent, and — when waiting — print the exact records to
add at the primary apex (the agent's KEY RR and an HSYNCPARAM pubkey flag).
States: update-unsupported / ready / foreign-key / waiting-for-key.`,
		Run: func(cmd *cobra.Command, args []string) {
			RunZoneProxyKey(role)
		},
	}
	proxyKey.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to report proxy-key state for")
	proxyKey.MarkFlagRequired("zone")

	nsec := &cobra.Command{
		Use:   "nsec",
		Short: "Prefix command, not usable by itself",
	}
	nsecGenerate := &cobra.Command{
		Use:   "generate",
		Short: "Generate NSEC records for a zone",
		Run: func(cmd *cobra.Command, args []string) {
			runZoneSimpleCmd(role, "generate-nsec")
		},
	}
	nsecShow := &cobra.Command{
		Use:   "show",
		Short: "Show the NSEC chain for a zone",
		Run: func(cmd *cobra.Command, args []string) {
			runZoneShowNsec(role)
		},
	}
	nsec.AddCommand(nsecGenerate, nsecShow)

	// Dynamic-zones management (add/delete/modify/list-dynamic). No --store
	// flag: dynamic zones are map-only. The --tsig-* flags are accepted now but
	// inert in Improvement 1 (a non-NOKEY key is rejected server-side).
	var dzPrimaryKey, dzTsigName, dzTsigSecret, dzTsigSecretFile, dzTsigAlgo string
	var dzPrimaries, dzOptions []string

	add := &cobra.Command{
		Use:   "add",
		Short: "Add a dynamic secondary zone at runtime (persists across restart)",
		Run: func(cmd *cobra.Command, args []string) {
			RunZoneAdd(role, dzPrimaries, dzPrimaryKey, dzOptions, dzTsigName, dzTsigSecret, dzTsigSecretFile, dzTsigAlgo)
		},
	}
	add.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to add")
	add.Flags().StringSliceVar(&dzPrimaries, "primaries", nil, "Primary (upstream) addresses [host:port], comma-separated")
	add.Flags().StringVar(&dzPrimaryKey, "primary-key", tdns.NOKEY, "Primary TSIG key name applied to all primaries (NOKEY for none)")
	add.Flags().StringSliceVar(&dzOptions, "options", nil, "Zone options (comma-separated)")
	add.Flags().StringVar(&dzTsigName, "tsig-name", "", "Inline TSIG key name; created in keystore if absent and applied to keyless primaries")
	add.Flags().StringVar(&dzTsigSecretFile, "tsig-secret-file", "", "File containing the inline TSIG secret (base64); preferred over --tsig-secret")
	add.Flags().StringVar(&dzTsigSecret, "tsig-secret", "", "Inline TSIG secret (base64). WARNING: visible in shell history / process list; prefer --tsig-secret-file")
	add.Flags().StringVar(&dzTsigAlgo, "tsig-algo", "", "Inline TSIG algorithm (default hmac-sha256)")
	add.MarkFlagRequired("zone")
	add.MarkFlagRequired("primaries")

	del := &cobra.Command{
		Use:   "delete",
		Short: "Delete a dynamic (API-managed) zone",
		Run: func(cmd *cobra.Command, args []string) {
			RunZoneDelete(role)
		},
	}
	del.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to delete")
	del.MarkFlagRequired("zone")

	modify := &cobra.Command{
		Use:   "modify",
		Short: "Modify a dynamic (API-managed) zone's primary or options",
		Run: func(cmd *cobra.Command, args []string) {
			RunZoneModify(role, dzPrimaries, dzPrimaryKey, dzOptions, dzTsigName, dzTsigSecret, dzTsigSecretFile, dzTsigAlgo)
		},
	}
	modify.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to modify")
	modify.Flags().StringSliceVar(&dzPrimaries, "primaries", nil, "New primary (upstream) addresses [host:port], comma-separated")
	modify.Flags().StringVar(&dzPrimaryKey, "primary-key", tdns.NOKEY, "New primary TSIG key name applied to all primaries (NOKEY for none)")
	modify.Flags().StringSliceVar(&dzOptions, "options", nil, "Zone options (comma-separated)")
	modify.Flags().StringVar(&dzTsigName, "tsig-name", "", "Inline TSIG key name; created in keystore if absent (existing keys cannot be rotated here)")
	modify.Flags().StringVar(&dzTsigSecretFile, "tsig-secret-file", "", "File containing the inline TSIG secret (base64); preferred over --tsig-secret")
	modify.Flags().StringVar(&dzTsigSecret, "tsig-secret", "", "Inline TSIG secret (base64). WARNING: visible in shell history / process list; prefer --tsig-secret-file")
	modify.Flags().StringVar(&dzTsigAlgo, "tsig-algo", "", "Inline TSIG algorithm (default hmac-sha256)")
	modify.MarkFlagRequired("zone")

	listDynamic := &cobra.Command{
		Use:   "list-dynamic",
		Short: "List dynamic zones (catalog members + API-managed) and their provisioning state",
		Run: func(cmd *cobra.Command, args []string) {
			RunZoneListDynamic(role)
		},
	}

	// `zone dnssec`: every DNSSEC operation for a zone — signing, policy, and
	// automated rollover. auto-rollover + policy-change moved here from
	// `keystore dnssec` (they act on a zone's signing state, not on key
	// material); policy-set/sign/resign/nsec moved down from the top-level
	// `zone` tree so all DNSSEC verbs live together.
	dnssecCmd := &cobra.Command{
		Use:   "dnssec",
		Short: "Zone DNSSEC operations: signing, policy, and automated rollover",
	}
	dnssecCmd.AddCommand(setPolicy, policyReset, newAutoRolloverPolicyChangeCmd(), newAutoRolloverCmd(role),
		sign, resign, nsec)

	c.AddCommand(list, desc, dnssecCmd, reload, bump, write, freeze, thaw, proxyKey, add, del, modify, listDynamic)
	// Role-independent extras attached to every zone tree. Each is built
	// fresh so the command pointer is unique per NewZoneCmd invocation.
	c.AddCommand(newZoneReadFakeCmd(), newZoneUpdateCmd(role), newZoneDsyncCmd(role))
	for _, e := range extras {
		c.AddCommand(e)
	}
	return c
}

// runZoneSimpleCmd runs a ZonePost command after PrepArgs("childzone")
// and only reports resp.Msg on success. Used by sign, freeze, thaw, generate-nsec.
func runZoneSimpleCmd(role, command string) {
	PrepArgs("childzone")

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command: command,
		Zone:    tdns.Globals.Zonename,
		Force:   force,
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}

	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}
}

func runZoneShowNsec(role string) {
	PrepArgs("childzone")

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "show-nsec-chain",
		Zone:    tdns.Globals.Zonename,
		Force:   force,
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}

	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}
	fmt.Printf("NSEC chain for zone \"%s\":\n", cr.Zone)
	for _, name := range cr.Names {
		fmt.Printf("%s\n", name)
	}
}

func RunZoneReload(parent string, args []string) {
	if tdns.Globals.Zonename == "" {
		fmt.Printf("Error: zone name not specified. Terminating.\n")
		os.Exit(1)
	}

	api, err := GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", parent, err)
	}

	resp, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "reload",
		Zone:    dns.Fqdn(tdns.Globals.Zonename),
		Force:   force,
		Wait:    showError,
		Timeout: errorTimeout,
	})

	if err != nil {
		fmt.Printf("Error from %q: %s\n", resp.AppName, err.Error())
		os.Exit(1)
	}

	if resp.Msg != "" {
		fmt.Printf("%s\n", resp.Msg)
	}
}

func RunZoneWrite(parent string, args []string) {
	PrepArgs("childzone")

	api, err := GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", parent, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "write-zone",
		Zone:    tdns.Globals.Zonename,
		Force:   force,
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}

	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}
}

func RunZoneSetPolicy(parent, policy string) {
	if tdns.Globals.Zonename == "" {
		fmt.Println("Error: zone name not specified")
		os.Exit(1)
	}
	api, err := GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", parent, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "policy-set",
		Zone:    dns.Fqdn(tdns.Globals.Zonename),
		Policy:  policy,
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}

	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}
}

// RunZoneResetPolicy drives the `zone dnssec policy-reset` command: it forwards
// --confirm as ZonePost.Force. Without --confirm the server returns a DRY-RUN
// preview (what the reset would do) instead of applying it, so we always send
// the request rather than refusing client-side.
func RunZoneResetPolicy(parent string, confirm bool) {
	if tdns.Globals.Zonename == "" {
		fmt.Println("Error: zone name not specified")
		os.Exit(1)
	}
	api, err := GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", parent, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "policy-reset",
		Zone:    dns.Fqdn(tdns.Globals.Zonename),
		Force:   confirm,
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}

	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}
}

func RunZoneProxyKey(parent string) {
	if tdns.Globals.Zonename == "" {
		fmt.Println("Error: zone name not specified")
		os.Exit(1)
	}
	api, err := GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", parent, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "proxy-key",
		Zone:    dns.Fqdn(tdns.Globals.Zonename),
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}
	if cr.Error {
		fmt.Printf("Error: %s\n", cr.ErrorMsg)
		os.Exit(1)
	}
	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}
}

func RunZoneList(parent string, args []string) {
	api, err := GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", parent, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "list-zones",
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}

	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}

	switch tdns.Globals.Verbose {
	case true:
		VerboseListZone(cr)
	case false:
		ListZones(cr)
	}
}

// RunZoneDesc drives `zone desc`: it asks the server for the single named zone
// (list-zones scoped to that zone, which also populates the extra DNSSEC detail
// fields) and prints the full describe block. Requires a zone.
func RunZoneDesc(parent string, args []string) {
	if tdns.Globals.Zonename == "" {
		fmt.Println("Error: zone name not specified")
		os.Exit(1)
	}
	zone := dns.Fqdn(tdns.Globals.Zonename)

	api, err := GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", parent, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "list-zones",
		Zone:    zone,
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}
	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}

	zconf, ok := cr.Zones[zone]
	if !ok {
		fmt.Printf("Error: server returned no data for zone %s\n", zone)
		os.Exit(1)
	}
	fmt.Print(DescribeZone(zconf))
}

func RunZoneBump(parent string, args []string) {
	PrepArgs("childzone")

	api, err := GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", parent, err)
	}

	resp, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "bump",
		Zone:    tdns.Globals.Zonename,
	})

	if err != nil {
		fmt.Printf("Error from %q: %s\n", resp.AppName, err.Error())
		os.Exit(1)
	}

	if resp.Msg != "" {
		fmt.Printf("%s\n", resp.Msg)
	}
}

// peerConfsFromAddrs builds a []PeerConf from comma-listed addresses, applying
// the single CLI key to each. Per-primary keys remain expressible via the
// structured YAML/API paths.
func peerConfsFromAddrs(addrs []string, key string) []tdns.PeerConf {
	out := make([]tdns.PeerConf, 0, len(addrs))
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		out = append(out, tdns.PeerConf{Addr: a, Key: key})
	}
	return out
}

// resolveTsigSecret returns the inline TSIG secret from --tsig-secret-file
// (preferred — not exposed in shell history or process listings) or the literal
// --tsig-secret flag. Setting both is an error.
func resolveTsigSecret(literal, file string) (string, error) {
	if file == "" {
		return literal, nil
	}
	if literal != "" {
		return "", fmt.Errorf("set only one of --tsig-secret or --tsig-secret-file")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("reading --tsig-secret-file %q: %w", file, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func RunZoneAdd(role string, primaries []string, primaryKey string, options []string, tsigName, tsigSecret, tsigSecretFile, tsigAlgo string) {
	if tdns.Globals.Zonename == "" {
		fmt.Println("Error: zone name not specified")
		os.Exit(1)
	}
	secret, err := resolveTsigSecret(tsigSecret, tsigSecretFile)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}
	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command:    "add",
		Zone:       dns.Fqdn(tdns.Globals.Zonename),
		Primaries:  peerConfsFromAddrs(primaries, primaryKey),
		Options:    options,
		TsigName:   tsigName,
		TsigSecret: secret,
		TsigAlgo:   tsigAlgo,
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}
	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}
}

func RunZoneDelete(role string) {
	if tdns.Globals.Zonename == "" {
		fmt.Println("Error: zone name not specified")
		os.Exit(1)
	}
	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}
	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "delete",
		Zone:    dns.Fqdn(tdns.Globals.Zonename),
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}
	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}
}

func RunZoneModify(role string, primaries []string, primaryKey string, options []string, tsigName, tsigSecret, tsigSecretFile, tsigAlgo string) {
	if tdns.Globals.Zonename == "" {
		fmt.Println("Error: zone name not specified")
		os.Exit(1)
	}
	secret, err := resolveTsigSecret(tsigSecret, tsigSecretFile)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}
	post := tdns.ZonePost{
		Command:    "modify",
		Zone:       dns.Fqdn(tdns.Globals.Zonename),
		Options:    options,
		TsigName:   tsigName,
		TsigSecret: secret,
		TsigAlgo:   tsigAlgo,
	}
	if peers := peerConfsFromAddrs(primaries, primaryKey); len(peers) > 0 {
		post.Primaries = peers
	}
	cr, err := SendZoneCommand(api, post)
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}
	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}
}

func RunZoneListDynamic(role string) {
	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}
	cr, err := SendZoneCommand(api, tdns.ZonePost{Command: "list-dynamic"})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
	}
	if len(cr.Zones) == 0 {
		fmt.Println("No dynamic zones.")
		return
	}
	names := make([]string, 0, len(cr.Zones))
	for name := range cr.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []string{"Zone|Type|Provisioning|Managed|Primary|Error"}
	for _, name := range names {
		zc := cr.Zones[name]
		managed := "catalog"
		if zc.ApiManaged {
			managed = "api"
		}
		errStr := ""
		if zc.Error {
			errStr = zc.ErrorMsg
		}
		out = append(out, fmt.Sprintf("%s|%s|%s|%s|%s|%s",
			name, zc.Type, zc.Provisioning, managed, peerConfAddrsString(zc.Primaries), errStr))
	}
	fmt.Println(columnize.SimpleFormat(out))
}

func SendZoneCommand(api *tdns.ApiClient, data tdns.ZonePost) (tdns.ZoneResponse, error) {
	var cr tdns.ZoneResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/zone", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return cr, fmt.Errorf("error from api post: %v", err)
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("error from json.Unmarshal: %v json: %q", err, string(buf))
	}

	if cr.Error {
		return cr, fmt.Errorf("%s", cr.ErrorMsg)
	}

	return cr, nil
}

func ListZones(cr tdns.ZoneResponse) {
	hdr := "Zone|Type|Store|"
	if showprimary {
		hdr += "Primary|"
	}
	if shownotify {
		hdr += "Notify|"
	}
	if showfile {
		hdr += "Zonefile|"
	}
	hdr += "Frozen|Dirty|Options"
	out := []string{}
	if tdns.Globals.ShowHeaders {
		out = append(out, hdr)
	}
	zoneLines := []string{}
	for zname, zconf := range cr.Zones {
		// Service-impacting errors collapse to a single ERROR row. A
		// non-service-impacting error (e.g. ConfigWarning: serving from a subset
		// of primaries) leaves the zone serving, so render it normally and
		// annotate it below rather than masquerading as an ERROR.
		if zconf.Error && tdns.ErrorTypeIsServiceImpacting(zconf.ErrorType) {
			line := fmt.Sprintf("%s|%s||||Error[%s]: %s", zname, "ERROR", tdns.ErrorTypeToString[zconf.ErrorType], zconf.ErrorMsg)
			zoneLines = append(zoneLines, line)
			continue
		}
		opts := []string{}
		for _, opt := range zconf.Options {
			opts = append(opts, tdns.ZoneOptionToString[opt])
		}
		sort.Strings(opts)
		line := fmt.Sprintf("%s|%s|%s|", zname, zconf.Type, zconf.Store)
		if showprimary {
			line += fmt.Sprintf("%s|", peerConfAddrsString(zconf.Primaries))
		}
		if shownotify {
			line += fmt.Sprintf("%s|", peerConfAddrsString(zconf.Notify))
		}
		if showfile {
			line += fmt.Sprintf("%s|", zconf.Zonefile)
		}
		line += fmt.Sprintf("%t|%t|%v", zconf.Frozen, zconf.Dirty, opts)
		if zconf.Error { // non-service-impacting => a warning; the zone still serves
			line += fmt.Sprintf(" [%s: %s]", tdns.ErrorTypeToString[zconf.ErrorType], zconf.ErrorMsg)
		}
		zoneLines = append(zoneLines, line)
	}
	sort.Slice(zoneLines, func(i, j int) bool {
		return zoneLines[i] < zoneLines[j]
	})
	out = append(out, zoneLines...)
	fmt.Printf("%s\n", columnize.SimpleFormat(out))
}

func VerboseListZone(cr tdns.ZoneResponse) {
	hdr := "Zone|Type|Store|"
	if showprimary {
		hdr += "Primary|"
	}
	if shownotify {
		hdr += "Notify|"
	}
	if showfile {
		hdr += "Zonefile|"
	}
	hdr += "Frozen|Dirty|Options"
	zoneLines := []string{}
	for zname, zconf := range cr.Zones {
		zoneLines = append(zoneLines, zoneBaseDetail(zname, zconf))
	}

	sort.Slice(zoneLines, func(i, j int) bool {
		return zoneLines[i] < zoneLines[j]
	})
	fmt.Printf("%s\n", columnize.SimpleFormat(zoneLines))
}

// zoneBaseDetail renders the per-zone detail block shared by VerboseListZone
// (`zone list -v`) and DescribeZone (`zone desc`): the zone header, error/warning
// state, type/store/options, effective DNSSEC policy + override, primaries/
// notify/file, and the frozen/dirty/config-source line. It returns the multi-line
// block (each line ending in a newline). Both renderers call it so they cannot
// drift; the caller passes the display name (VerboseListZone uses the map key,
// DescribeZone uses zconf.Name — equal in practice). `zone list -v` output must
// stay byte-identical — see TestVerboseListZone_GoldenParity.
func zoneBaseDetail(name string, zconf tdns.ZoneConf) string {
	var b strings.Builder
	fmt.Fprintf(&b, "zone: %s\n", name)
	if zconf.Error {
		// A service-impacting error is ERROR; a non-service-impacting warning
		// (e.g. ConfigWarning) leaves the zone serving — render it as such,
		// matching ListZones rather than masquerading as ERROR.
		if tdns.ErrorTypeIsServiceImpacting(zconf.ErrorType) {
			fmt.Fprintf(&b, "\tState: ERROR ErrorType: %s ErrorMsg: %s\n", tdns.ErrorTypeToString[zconf.ErrorType], zconf.ErrorMsg)
		} else {
			fmt.Fprintf(&b, "\tState: serving Warning[%s]: %s\n", tdns.ErrorTypeToString[zconf.ErrorType], zconf.ErrorMsg)
		}
	}
	opts := []string{}
	for _, opt := range zconf.Options {
		opts = append(opts, tdns.ZoneOptionToString[opt])
	}
	sort.Strings(opts)
	fmt.Fprintf(&b, "\tType: %s\tStore: %s\tOptions: %v\n", zconf.Type, zconf.Store, opts)

	if zconf.EffectiveDnssecPolicy != "" {
		pol := zconf.EffectiveDnssecPolicy
		if zconf.DnssecPolicyOverridden {
			if zconf.DnssecPolicyConfigBase != "" {
				pol += fmt.Sprintf(" (override from config: %s)", zconf.DnssecPolicyConfigBase)
			} else {
				pol += " (override; set live, not in config)"
			}
		}
		fmt.Fprintf(&b, "\tDNSSEC policy: %s\n", pol)
	}

	fmt.Fprintf(&b, "\tPrimary: %s\tNotify: %s\tFile: %s\n", peerConfAddrsString(zconf.Primaries), peerConfAddrsString(zconf.Notify), zconf.Zonefile)

	// Check for catalog zone flags
	isCatalogZone := false
	isAutoConfigured := false
	for _, opt := range zconf.Options {
		if opt == tdns.OptCatalogZone {
			isCatalogZone = true
		}
		if opt == tdns.OptAutomaticZone {
			isAutoConfigured = true
		}
	}

	configInfo := ""
	if isCatalogZone {
		configInfo = "Catalog Zone"
	} else if isAutoConfigured {
		if zconf.SourceCatalog != "" {
			configInfo = fmt.Sprintf("Config: auto (from catalog %s)", zconf.SourceCatalog)
		} else {
			configInfo = "Config: auto"
		}
	} else {
		configInfo = "Config: manual"
	}

	fmt.Fprintf(&b, "\tFrozen: %t\tDirty: %t\t%s\n", zconf.Frozen, zconf.Dirty, configInfo)
	return b.String()
}

// DescribeZone renders the full single-zone detail block for `zone desc`:
// everything VerboseListZone shows for a zone (state, type/store/options,
// effective DNSSEC policy + override, primaries/notify/file, frozen/dirty/config
// source) plus two sections that are only available via `zone desc` — the
// last-applied DNSSEC-policy record and the bound policy's algorithm/lifetime/
// sig-validity detail. It returns the text (trailing newline included) so it is
// straightforward to unit test; RunZoneDesc prints the result.
func DescribeZone(zconf tdns.ZoneConf) string {
	var b strings.Builder
	// Shared base block (identical to what `zone list -v` renders for the zone).
	b.WriteString(zoneBaseDetail(zconf.Name, zconf))

	// Section 1: last-applied DNSSEC policy record (from the keystore). A backend
	// read failure is surfaced distinctly from a genuinely absent record so an
	// operator diagnosing DNSSEC state isn't misled by "(not recorded)".
	switch {
	case zconf.AppliedError != "":
		fmt.Fprintf(&b, "\tApplied policy: (lookup failed: %s)\n", zconf.AppliedError)
	case zconf.AppliedPolicy != "":
		src := zconf.AppliedSource
		if src == "" {
			src = "(unknown)"
		}
		at := zconf.AppliedAt
		if at == "" {
			at = "(unknown)"
		}
		fmt.Fprintf(&b, "\tApplied policy: %s\tSource: %s\tApplied at: %s\n", zconf.AppliedPolicy, src, at)
	default:
		b.WriteString("\tApplied policy: (not recorded)\n")
	}

	// Section 2: bound-policy algorithm / lifetime / sig-validity detail.
	b.WriteString(describePolicyDetail(zconf))

	return b.String()
}

// describePolicyDetail renders the bound-policy DNSSEC detail block for
// `zone desc`. It degrades gracefully: a zone with no bound policy prints
// "not signed"; a bound policy name that the server could not resolve in the
// running config prints "policy unavailable". Otherwise it renders mode, the
// role algorithms (KSK/ZSK, or CSK in csk mode), key lifetimes and RRSIG
// validity, and surfaces the policy's parse Error when set.
func describePolicyDetail(zconf tdns.ZoneConf) string {
	pd := zconf.PolicyDetail
	if pd == nil {
		if zconf.EffectiveDnssecPolicy == "" {
			return "\tDNSSEC detail: not signed\n"
		}
		return fmt.Sprintf("\tDNSSEC detail: policy unavailable (%s)\n", zconf.EffectiveDnssecPolicy)
	}

	var b strings.Builder
	mode := pd.Mode
	if mode == "" {
		mode = "(unset)"
	}
	fmt.Fprintf(&b, "\tDNSSEC detail: Mode: %s\n", mode)
	if pd.Error != "" {
		fmt.Fprintf(&b, "\t\tError: %s\n", pd.Error)
	}
	if pd.Mode == tdns.DnssecPolicyModeCSK {
		fmt.Fprintf(&b, "\t\tCSK algorithm: %s\n", algName(pd.Algorithm))
		fmt.Fprintf(&b, "\t\tCSK lifetime: %s\n", secsToDuration(pd.CSKLifetime))
	} else {
		fmt.Fprintf(&b, "\t\tKSK algorithm: %s\tZSK algorithm: %s\n", algName(pd.KSKAlgorithm), algName(pd.ZSKAlgorithm))
		fmt.Fprintf(&b, "\t\tKSK lifetime: %s\tZSK lifetime: %s\n", secsToDuration(pd.KSKLifetime), secsToDuration(pd.ZSKLifetime))
	}
	fmt.Fprintf(&b, "\t\tSigValidity: default=%s DNSKEY=%s DS=%s\n",
		secsToDuration(pd.SigValidityDefault), secsToDuration(pd.SigValidityDNSKEY), secsToDuration(pd.SigValidityDS))
	return b.String()
}

// algName renders a DNSSEC algorithm number as its mnemonic, falling back to the
// decimal number for algorithms miekg/dns does not name (matching how dns prints
// an unknown algorithm).
func algName(alg uint8) string {
	if name := dns.AlgorithmToString[alg]; name != "" {
		return name
	}
	return strconv.Itoa(int(alg))
}

// secsToDuration renders a seconds count as a human duration (e.g. "720h0m0s");
// 0 renders as "0s".
func secsToDuration(secs uint32) string {
	return (time.Duration(secs) * time.Second).String()
}
