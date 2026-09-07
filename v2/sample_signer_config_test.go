package tdns

import (
	"strings"
	"testing"
)

// The shipped tdns-signer samples go through the same decode pipeline as the
// tdns-auth ones (see sample_config_test.go for why that matters: every defect
// those tests exist for shipped in a sample that was valid YAML).
//
// These add the checks that are specific to what a signer's config MUST say to
// do its job at all.

func TestSampleSignerZonesConfigDecodes(t *testing.T) {
	var result struct {
		Zones []ZoneConf `yaml:"zones"`
	}
	md := decodeSample(t, "../cmdv2/signer/signer-zones.sample.yaml", &result)

	if len(result.Zones) == 0 {
		t.Fatal("no zones decoded from the signer sample")
	}
	if len(md.Unused) > 0 {
		t.Errorf("signer zones sample has config keys the loader silently drops: %v", md.Unused)
	}

	sawSigningSecondary, sawNotify, sawDownstreams := false, false, false
	for _, z := range result.Zones {
		checkZoneConf(t, "zone", z)

		inline := false
		for _, o := range z.OptionsStrs {
			if strings.ToLower(strings.TrimSpace(o)) == "inline-signing" {
				inline = true
			}
		}

		// The whole point of the app. A secondary WITHOUT inline-signing may
		// not originate content, so it serves the zone exactly as received --
		// unsigned. A sample that lost this option would document a signer
		// that does not sign.
		if z.Type == "secondary" && inline {
			sawSigningSecondary = true
		}
		// A primary here would mean the sample had drifted into being an
		// ordinary auth config.
		if z.Type == "primary" {
			t.Errorf("zone %s: type primary in the signer sample -- a bump-on-the-wire "+
				"signer holds its zones as secondary + inline-signing", z.Name)
		}
		// inline-signing without upstreams is a zone with nothing to sign.
		if inline && len(z.Primaries) == 0 {
			t.Errorf("zone %s: inline-signing but no upstreams: -- nothing to transfer in", z.Name)
		}
		if len(z.Notify) > 0 {
			sawNotify = true
		}
		if len(z.Downstreams) > 0 {
			sawDownstreams = true
		}
	}

	if !sawSigningSecondary {
		t.Error("no zone in the signer sample is `type: secondary` with the " +
			"inline-signing option -- that pair IS the bump-on-the-wire signer")
	}
	// Signing a zone nobody can transfer, or transferring without telling
	// anyone, is half a pipeline. Both halves belong in the sample.
	if !sawDownstreams {
		t.Error("no zone in the signer sample has a downstreams: ACL -- nothing could pull the signed zone")
	}
	if !sawNotify {
		t.Error("no zone in the signer sample has a notify: list -- downstreams would wait for their refresh timer")
	}
}

// The signer's main config must decode with nothing silently dropped, and must
// carry the DNSSEC policy its zones name.
func TestSampleSignerConfigDecodes(t *testing.T) {
	var conf Config
	md := decodeSample(t, "../cmdv2/signer/tdns-signer.sample.yaml", &conf)

	// Keys that are real but are NOT consumed through the Config struct, so
	// mapstructure reports them as unused and is right to:
	//
	//   include        expanded by MergeViperIncludes before this decode runs
	//   resignerengine read straight out of viper as
	//                  viper.GetInt("resignerengine.interval")
	//                  (v2/runtime_config.go), with no field on Config
	//
	// Anything else in md.Unused is a key the loader would silently drop --
	// which is how a sample comes to document an option that does nothing.
	consumedElsewhere := map[string]bool{"include": true, "resignerengine": true}
	for _, k := range md.Unused {
		if consumedElsewhere[strings.SplitN(k, ".", 2)[0]] {
			continue
		}
		t.Errorf("signer sample has a config key the loader silently drops: %q", k)
	}

	if conf.Db.File == "" {
		t.Error("signer sample has no db.file: the keystore lives there, so the signer cannot hold keys")
	}
	if len(conf.Dnssec.Policies) == 0 {
		t.Fatal("signer sample defines no dnssec policies: every inline-signing zone would fail to load")
	}

	// Tie the two samples together the way TestSampleZonesReferenceDefinedTemplates
	// does: a zone naming a policy that does not exist is quarantined at load.
	var zres struct {
		Zones []ZoneConf `yaml:"zones"`
	}
	decodeSample(t, "../cmdv2/signer/signer-zones.sample.yaml", &zres)
	for _, z := range zres.Zones {
		if z.DnssecPolicy == "" || z.DnssecPolicy == "none" {
			continue
		}
		if _, ok := conf.Dnssec.Policies[z.DnssecPolicy]; !ok {
			t.Errorf("zone %s names dnssecpolicy %q, which tdns-signer.sample.yaml does not define",
				z.Name, z.DnssecPolicy)
		}
	}
}
