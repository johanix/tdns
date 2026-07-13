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

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// Guard marker (design doc §6.5): generated zones carry
//
//	_tdns-debug.<zone>. TXT "test-id=<id>"
//
// and destructive actors refuse a zone without it unless --unsafe-zone is
// given. Cheap insurance against aiming a mutation barrage at a real zone.
const MarkerLabel = "_tdns-debug"

func MarkerRR(zone, id string) string {
	return fmt.Sprintf("%s.%s 3600 IN TXT \"test-id=%s\"", MarkerLabel, dns.Fqdn(zone), id)
}

// ChurnLabel is the subtree all churn records live under. The SIG(0) key is
// named exactly "_churn.<zone>" so a selfsub update policy grants the key
// authority over precisely this subtree and nothing else (doc §6.1).
const ChurnLabel = "_churn"

type ChurnProvisionInput struct {
	BaseZone       string // parent under which <id>.<base> is invented (required)
	DnsServer      string // addr[:port]; a literal IP also becomes the ns glue
	Target         string // apiservers entry name (informational, recorded)
	PublishCadence string // default "20s" (snapshot-branch config key)
	ConfigDir      string // base dir; artifacts land in <ConfigDir>/<id> (default DefaultConfigDir)
	OutDir         string // explicit artifact dir override (wins over ConfigDir)
}

type ChurnProvision struct {
	Record      *TestRecord
	ZoneFile    string
	SnippetFile string
	Todo        []string
}

// GenerateChurnConfig implements the provisioning stage of `test churn
// --generate-config` (doc §6.3): allocate an identity, generate the SIG(0)
// keypair locally (only the public key is ever destined for the server),
// emit the zone file and the config snippet, and record everything in the
// state. It does NOT touch any server — API auto-install of keys is M3.
func GenerateChurnConfig(st *State, in ChurnProvisionInput) (*ChurnProvision, error) {
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

	rec := st.Allocate("churn")
	zone := rec.Id + "." + base
	keyName := ChurnLabel + "." + zone

	outDir := in.OutDir
	if outDir == "" {
		base := in.ConfigDir
		if base == "" {
			base = DefaultConfigDir
		}
		outDir = filepath.Join(base, rec.Id)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, err
	}

	// Local SIG(0) keypair. ED25519: small, fast, deterministic signatures.
	pkc, err := tdns.GenerateKeyMaterial(keyName, dns.TypeKEY, dns.ED25519, "")
	if err != nil {
		return nil, fmt.Errorf("SIG(0) key generation for %s: %v", keyName, err)
	}
	keyFile := filepath.Join(outDir, rec.Id+"-sig0.key")
	privFile := filepath.Join(outDir, rec.Id+"-sig0.private")
	if err := os.WriteFile(keyFile, []byte(pkc.KeyRR.String()+"\n"), 0644); err != nil {
		return nil, err
	}
	// PEM, as tdns stores/exports keys; PrepareKeyCache() reads this back.
	if err := os.WriteFile(privFile, []byte(pkc.PrivateKey), 0600); err != nil {
		return nil, err
	}

	// Zone file: minimal apex + guard marker (+ ns glue when the DNS target
	// is a literal IP). Everything else arrives via DNS UPDATE.
	zoneFile := filepath.Join(outDir, strings.TrimSuffix(zone, ".")+".zone")
	if err := os.WriteFile(zoneFile, []byte(bootstrapZone(zone, rec.Id, in.DnsServer)), 0644); err != nil {
		return nil, err
	}

	// Config snippet the operator adds to the target server. It points
	// zonefile: at the emitted zone file directly (no copy step, nothing to
	// keep consistent by hand); the server needs read access to it.
	snippetFile := filepath.Join(outDir, rec.Id+"-zones.yaml")
	if err := os.WriteFile(snippetFile, []byte(configSnippet(zone, rec.Id, in.PublishCadence, zoneFile)), 0644); err != nil {
		return nil, err
	}

	rec.BaseZone = base
	rec.Zone = zone
	rec.Target = in.Target
	rec.DnsServer = in.DnsServer
	rec.Sig0KeyName = keyName
	rec.Sig0KeyFile = keyFile
	rec.Sig0PrivFile = privFile
	rec.ArtifactDir = outDir

	todo := []string{
		fmt.Sprintf("merge %s into the server's zones: config (it points zonefile: at %s directly — no copy needed; adjust downstreams prefix if tdns-debug runs off-host)", snippetFile, zoneFile),
		fmt.Sprintf("trust the SIG(0) public key: tdns-cli auth truststore add --src %s --child %s", keyFile, keyName),
		"reload the server (or restart)",
		fmt.Sprintf("then run: tdns-debug test churn --test %s", rec.Id),
	}
	rec.OperatorSteps = todo
	rec.AddStage("provisioned", fmt.Sprintf("zone %s, artifacts in %s", zone, outDir))

	return &ChurnProvision{Record: rec, ZoneFile: zoneFile, SnippetFile: snippetFile, Todo: todo}, nil
}

// bootstrapZone synthesizes the minimal apex: SOA + NS + guard marker, with
// ns address glue when the DNS target is a literal IP. (The richer
// listener-derived synthesis is the dynamic-primary-zones server feature —
// this is the client-side stand-in until that lands.)
func bootstrapZone(zone, id, dnsServer string) string {
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
	return b.String()
}

// configSnippet emits the zone declaration for the target server: update
// policy selfsub/TXT paired with the _churn.<zone> key name (the selfsub
// grant covers exactly the churn subtree), AXFR open to the adjusted
// prefix, publish-cadence for snapshot-branch servers (ignored elsewhere).
// zoneFile is the absolute path of the emitted zone file, referenced
// directly so there is no copy step and nothing to keep consistent by hand.
func configSnippet(zone, id, cadence, zoneFile string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# tdns-debug %s — add this entry to the server's zones: LIST.\n", id)
	fmt.Fprintf(&b, "# zonefile points at the emitted file directly; adjust downstreams prefix if tdns-debug runs off-host.\n")
	fmt.Fprintf(&b, "zones:\n")
	fmt.Fprintf(&b, "   - name: %s\n", zone)
	fmt.Fprintf(&b, "     type: primary\n")
	fmt.Fprintf(&b, "     store: map\n")
	fmt.Fprintf(&b, "     zonefile: %s\n", zoneFile)
	fmt.Fprintf(&b, "     update-policy:\n")
	fmt.Fprintf(&b, "        zone:\n")
	fmt.Fprintf(&b, "           type: selfsub   # %s.%s owns names under itself\n", ChurnLabel, zone)
	fmt.Fprintf(&b, "           rrtypes: [ TXT ]\n")
	fmt.Fprintf(&b, "     downstreams:\n")
	fmt.Fprintf(&b, "        - prefix: 127.0.0.1/32   # adjust: tdns-debug host\n")
	fmt.Fprintf(&b, "          key: NOKEY\n")
	fmt.Fprintf(&b, "     publish-cadence: %s   # snapshot-correctness branch only; harmless elsewhere\n", cadence)
	return b.String()
}
