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
	"strings"

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
		Short: "Bump SOA serial and epoch (if any) in tdns-auth version of zone",
		Run:   func(cmd *cobra.Command, args []string) { RunZoneBump(role, args) },
	}

	var setPolicyName string
	setPolicy := &cobra.Command{
		Use:   "set-policy",
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
	var dzPrimaryAddr, dzPrimaryKey, dzTsigName, dzTsigSecret, dzTsigAlgo string
	var dzOptions []string

	add := &cobra.Command{
		Use:   "add",
		Short: "Add a dynamic secondary zone at runtime (persists across restart)",
		Run: func(cmd *cobra.Command, args []string) {
			RunZoneAdd(role, dzPrimaryAddr, dzPrimaryKey, dzOptions, dzTsigName, dzTsigSecret, dzTsigAlgo)
		},
	}
	add.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to add")
	add.Flags().StringVar(&dzPrimaryAddr, "primary-addr", "", "Primary (upstream) address [host:port]")
	add.Flags().StringVar(&dzPrimaryKey, "primary-key", tdns.NOKEY, "Primary TSIG key name (NOKEY for none)")
	add.Flags().StringSliceVar(&dzOptions, "options", nil, "Zone options (comma-separated)")
	add.Flags().StringVar(&dzTsigName, "tsig-name", "", "TSIG key name (inert until TSIG support lands)")
	add.Flags().StringVar(&dzTsigSecret, "tsig-secret", "", "TSIG secret (inert until TSIG support lands)")
	add.Flags().StringVar(&dzTsigAlgo, "tsig-algo", "", "TSIG algorithm (inert until TSIG support lands)")
	add.MarkFlagRequired("zone")
	add.MarkFlagRequired("primary-addr")

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
			RunZoneModify(role, dzPrimaryAddr, dzPrimaryKey, dzOptions)
		},
	}
	modify.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to modify")
	modify.Flags().StringVar(&dzPrimaryAddr, "primary-addr", "", "New primary (upstream) address [host:port]")
	modify.Flags().StringVar(&dzPrimaryKey, "primary-key", tdns.NOKEY, "New primary TSIG key name (NOKEY for none)")
	modify.Flags().StringSliceVar(&dzOptions, "options", nil, "Zone options (comma-separated)")
	modify.MarkFlagRequired("zone")

	listDynamic := &cobra.Command{
		Use:   "list-dynamic",
		Short: "List dynamic zones (catalog members + API-managed) and their provisioning state",
		Run: func(cmd *cobra.Command, args []string) {
			RunZoneListDynamic(role)
		},
	}

	c.AddCommand(list, nsec, sign, resign, reload, bump, write, freeze, thaw, setPolicy, proxyKey, add, del, modify, listDynamic)
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
		Command: "set-policy",
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

func RunZoneAdd(role, primaryAddr, primaryKey string, options []string, tsigName, tsigSecret, tsigAlgo string) {
	if tdns.Globals.Zonename == "" {
		fmt.Println("Error: zone name not specified")
		os.Exit(1)
	}
	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}
	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command:    "add",
		Zone:       dns.Fqdn(tdns.Globals.Zonename),
		Primaries:  []tdns.PeerConf{{Addr: primaryAddr, Key: primaryKey}},
		Options:    options,
		TsigName:   tsigName,
		TsigSecret: tsigSecret,
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

func RunZoneModify(role, primaryAddr, primaryKey string, options []string) {
	if tdns.Globals.Zonename == "" {
		fmt.Println("Error: zone name not specified")
		os.Exit(1)
	}
	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}
	post := tdns.ZonePost{
		Command: "modify",
		Zone:    dns.Fqdn(tdns.Globals.Zonename),
		Options: options,
	}
	if primaryAddr != "" {
		post.Primaries = []tdns.PeerConf{{Addr: primaryAddr, Key: primaryKey}}
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
		if zconf.Error {
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
		line := fmt.Sprintf("zone: %s\n", zname)
		if zconf.Error {
			line += fmt.Sprintf("\tState: ERROR ErrorType: %s ErrorMsg: %s\n", tdns.ErrorTypeToString[zconf.ErrorType], zconf.ErrorMsg)
		}
		opts := []string{}
		for _, opt := range zconf.Options {
			opts = append(opts, tdns.ZoneOptionToString[opt])
		}
		sort.Strings(opts)
		line += fmt.Sprintf("\tType: %s\tStore: %s\tOptions: %v\n", zconf.Type, zconf.Store, opts)

		if zconf.EffectiveDnssecPolicy != "" {
			pol := zconf.EffectiveDnssecPolicy
			if zconf.DnssecPolicyOverridden {
				if zconf.DnssecPolicyConfigBase != "" {
					pol += fmt.Sprintf(" (override from config: %s)", zconf.DnssecPolicyConfigBase)
				} else {
					pol += " (override; set live, not in config)"
				}
			}
			line += fmt.Sprintf("\tDNSSEC policy: %s\n", pol)
		}

		line += fmt.Sprintf("\tPrimary: %s\tNotify: %s\tFile: %s\n", peerConfAddrsString(zconf.Primaries), peerConfAddrsString(zconf.Notify), zconf.Zonefile)

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

		line += fmt.Sprintf("\tFrozen: %t\tDirty: %t\t%s\n", zconf.Frozen, zconf.Dirty, configInfo)
		zoneLines = append(zoneLines, line)
	}

	sort.Slice(zoneLines, func(i, j int) bool {
		return zoneLines[i] < zoneLines[j]
	})
	fmt.Printf("%s\n", columnize.SimpleFormat(zoneLines))
}
