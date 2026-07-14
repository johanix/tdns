/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
)

// DefaultReloadAlgorithm is the signing algorithm the reload test provisions
// by default. SQISIGN1 is deliberately expensive: a slow online-signing pass
// widens the reload re-sign window so the unsigned-window defect is easy to
// sample. Overridable with --algorithm (e.g. a faster PQ alg for iteration).
const DefaultReloadAlgorithm = "SQISIGN1"

// DefaultReloadZoneSize is the number of filler RRsets the reload test zone
// carries. Large enough that one online-signing pass is slow (the window).
const DefaultReloadZoneSize = 10000

// ReloadProvisionInput parameterizes `test reload --generate-config`. Unlike
// churn, the reload test drives no dynamic updates (the window is reload-
// driven), so it needs no SIG(0) key — it only reloads, transfers and queries.
type ReloadProvisionInput struct {
	BaseZone       string // parent under which <id>.<base> is invented (required)
	DnsServer      string // addr[:port]; a literal IP also becomes the ns glue
	Target         string // apiservers entry name (informational, recorded)
	PublishCadence string // default "20s" (snapshot-branch config key)
	ConfigDir      string // base dir; artifacts land in <ConfigDir>/<id>
	OutDir         string // explicit artifact dir override (wins over ConfigDir)
	ZoneSize       int    // filler RRsets (default DefaultReloadZoneSize)
	Algorithm      string // signing algorithm (default DefaultReloadAlgorithm)
}

type ReloadProvision struct {
	Record      *TestRecord
	ZoneFile    string
	SnippetFile string
	Todo        []string
}

// GenerateReloadConfig is the provisioning stage of `test reload
// --generate-config`: allocate an identity, emit a large online-signed zone
// file and the matching config snippet (a single-algorithm DNSSEC policy plus
// the zone that references it), and record everything in state. It touches no
// server. Deliberately standalone from GenerateChurnConfig so the churn path
// (the snapshot-branch merge gate) is untouched; the small overlap in apex/
// snippet emission is the price of that isolation.
func GenerateReloadConfig(st *State, in ReloadProvisionInput) (*ReloadProvision, error) {
	if in.BaseZone == "" {
		return nil, fmt.Errorf("--base-zone is required")
	}
	base := dns.Fqdn(strings.ToLower(in.BaseZone))
	if _, ok := dns.IsDomainName(base); !ok {
		return nil, fmt.Errorf("invalid base zone %q", in.BaseZone)
	}
	if in.PublishCadence == "" {
		in.PublishCadence = "20s"
	}
	if in.ZoneSize <= 0 {
		in.ZoneSize = DefaultReloadZoneSize
	}
	if in.Algorithm == "" {
		in.Algorithm = DefaultReloadAlgorithm
	}

	rec := st.Allocate("reload")
	zone := rec.Id + "." + base

	outDir := in.OutDir
	if outDir == "" {
		b := in.ConfigDir
		if b == "" {
			b = DefaultConfigDir
		}
		outDir = filepath.Join(b, rec.Id)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}

	zoneFile := filepath.Join(outDir, strings.TrimSuffix(zone, ".")+".zone")
	if err := os.WriteFile(zoneFile, []byte(reloadZone(zone, rec.Id, in.DnsServer, in.ZoneSize)), 0o644); err != nil {
		return nil, err
	}

	snippetFile := filepath.Join(outDir, rec.Id+"-zones.yaml")
	if err := os.WriteFile(snippetFile, []byte(reloadConfigSnippet(zone, rec.Id, in.PublishCadence, zoneFile, in.Algorithm)), 0o644); err != nil {
		return nil, err
	}

	rec.BaseZone = base
	rec.Zone = zone
	rec.Target = in.Target
	rec.DnsServer = in.DnsServer
	rec.ArtifactDir = outDir
	if err := WriteArtifactMarker(outDir, rec.Id); err != nil {
		return nil, fmt.Errorf("writing artifact marker: %w", err)
	}

	todo := []string{
		fmt.Sprintf("merge the dnssec.policies and zones entries from %s into the server's config (the zone points zonefile: at %s directly — no copy; adjust downstreams prefix if tdns-debug runs off-host)", snippetFile, zoneFile),
		fmt.Sprintf("confirm the server supports %s: tdns-cli auth keystore dnssec algorithms | grep -i %s", in.Algorithm, in.Algorithm),
		"reload the server (or restart) and confirm the zone signs (apex DNSKEY + RRSIGs appear)",
		fmt.Sprintf("then run: tdns-debug test reload --test %s", rec.Id),
	}
	rec.OperatorSteps = todo
	rec.AddStage("provisioned", fmt.Sprintf("zone %s (%d RRsets, %s-signed), artifacts in %s", zone, in.ZoneSize, in.Algorithm, outDir))

	return &ReloadProvision{Record: rec, ZoneFile: zoneFile, SnippetFile: snippetFile, Todo: todo}, nil
}

// reloadZone synthesizes the apex (SOA + NS + guard marker + ns glue) plus
// ZoneSize filler A RRsets. Distinct owners (one RRset each) make the online-
// signing pass cost scale with ZoneSize — that cost IS the re-sign window the
// reload test hunts. Rdata is constant (TEST-NET-1); only the RRset count and
// per-signature cost matter.
func reloadZone(zone, id, dnsServer string, zoneSize int) string {
	var b strings.Builder
	ns := "ns." + zone
	fmt.Fprintf(&b, "$ORIGIN %s\n$TTL 3600\n", zone)
	fmt.Fprintf(&b, "%s IN SOA %s hostmaster.%s 1 3600 600 604800 300\n", zone, ns, zone)
	fmt.Fprintf(&b, "%s IN NS %s\n", zone, ns)
	fmt.Fprintf(&b, "%s\n", MarkerRR(zone, id))

	host := dnsServer
	if h, _, err := net.SplitHostPort(dnsServer); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			fmt.Fprintf(&b, "%s IN A %s\n", ns, ip)
		} else {
			fmt.Fprintf(&b, "%s IN AAAA %s\n", ns, ip)
		}
	}
	for i := 1; i <= zoneSize; i++ {
		fmt.Fprintf(&b, "host%05d IN A 192.0.2.1\n", i)
	}
	return b.String()
}

// reloadConfigSnippet emits a single-algorithm DNSSEC policy (KSK and ZSK both
// inherit the policy `algorithm:`, static keys) plus the primary zone that
// references it with online-signing enabled. Two config sections; the operator
// merges each into the corresponding part of the server config.
func reloadConfigSnippet(zone, id, cadence, zoneFile, algorithm string) string {
	policyName := id + "-" + strings.ToLower(algorithm)
	var b strings.Builder
	fmt.Fprintf(&b, "# tdns-debug %s — reload test (%s-signed).\n", id, algorithm)
	fmt.Fprintf(&b, "# Merge the dnssec.policies entry into your dnssec: section and the\n")
	fmt.Fprintf(&b, "# zones entry into your zones: section.\n\n")

	fmt.Fprintf(&b, "dnssec:\n")
	fmt.Fprintf(&b, "   policies:\n")
	fmt.Fprintf(&b, "      %s:\n", policyName)
	fmt.Fprintf(&b, "         algorithm: %s   # single algorithm: KSK and ZSK both inherit it\n", algorithm)
	fmt.Fprintf(&b, "         ksk:\n")
	fmt.Fprintf(&b, "            lifetime: forever\n")
	fmt.Fprintf(&b, "         zsk:\n")
	fmt.Fprintf(&b, "            lifetime: forever\n")
	fmt.Fprintf(&b, "         csk:\n")
	fmt.Fprintf(&b, "            lifetime: none\n")
	fmt.Fprintf(&b, "         sigvalidity:\n")
	fmt.Fprintf(&b, "            default: 14d\n")
	fmt.Fprintf(&b, "            dnskey:  30d\n")
	fmt.Fprintf(&b, "            ds:      14d\n\n")

	fmt.Fprintf(&b, "zones:\n")
	fmt.Fprintf(&b, "   - name: %s\n", zone)
	fmt.Fprintf(&b, "     type: primary\n")
	fmt.Fprintf(&b, "     store: map\n")
	fmt.Fprintf(&b, "     zonefile: %s\n", zoneFile)
	// online-signing enables the online signer; dnssecpolicy supplies the
	// algorithm/lifetimes. Both are required for the zone to sign.
	fmt.Fprintf(&b, "     options: [ online-signing ]\n")
	fmt.Fprintf(&b, "     dnssecpolicy: %s\n", policyName)
	fmt.Fprintf(&b, "     downstreams:\n")
	fmt.Fprintf(&b, "        - prefix: 127.0.0.1/32   # adjust: tdns-debug host (AXFR)\n")
	fmt.Fprintf(&b, "          key: NOKEY\n")
	fmt.Fprintf(&b, "     publish-cadence: %s   # snapshot-correctness branch only; harmless elsewhere\n", cadence)
	return b.String()
}
