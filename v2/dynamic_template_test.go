package tdns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tests for templates on API zones (dynamic_template.go): a secondary
// takes its outbound settings from a blessed template, the template owns
// them (never persisted, re-expanded at boot and on reload), and modify can
// keep, set and clear the template.

const opKey = "op-key."

// withOpKey gives conf a keystore holding the operator key the test
// templates bind their downstreams and NOTIFY targets to.
func withOpKey(t *testing.T, conf *Config) {
	t.Helper()
	store := NewTsigKeyStore()
	store.Add(TsigDetails{Name: opKey, Algorithm: "hmac-sha256", Secret: "b3BlcmF0b3Ita2V5LXNlY3JldA=="})
	conf.Internal.TsigKeyStore = store
}

// hubTemplate is a blessed secondary template that sends a zone on to two
// downstreams with the operator key. It also sets fields an API secondary
// must NOT take from a template (primaries, options, transfer-src), so the
// tests can see that they are ignored.
func hubTemplate() ZoneConf {
	three := 3
	return ZoneConf{
		Name:         "hub-out",
		Type:         "secondary",
		DynamicZones: true,
		Notify: []PeerConf{
			{Addr: "192.0.2.10", Key: opKey},
			{Addr: "192.0.2.11:5353", Key: opKey},
		},
		Downstreams:         []AclEntry{{Prefix: "192.0.2.0/24", Key: opKey}},
		DownstreamAuth:      []string{"tsig"},
		AllowNotify:         []AclEntry{{Prefix: "198.51.100.1/32", Key: NOKEY}},
		NotifyRetries:       &three,
		NotifyRetryInterval: "4s",
		// Ignored for an API secondary:
		Primaries:   []PeerConf{{Addr: "203.0.113.66:53", Key: NOKEY}},
		OptionsStrs: []string{"allow-updates"},
		TransferSrc: []string{"192.0.2.99"},
	}
}

func secondaryIn(name string) DynamicZoneInput {
	return DynamicZoneInput{
		Name:      name,
		Type:      Secondary,
		Primaries: []PeerConf{{Addr: "198.51.100.1:53", Key: NOKEY}},
	}
}

func TestProvisionDynamicSecondary_TemplateGivesOutboundOnly(t *testing.T) {
	resetZonesForTest()
	conf, ch := newTestConfigForCores(t)
	withOpKey(t, conf)
	withTestTemplates(t, map[string]ZoneConf{"hub-out": hubTemplate()})

	in := secondaryIn("cust.example")
	in.Template = "hub-out"
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("add with a blessed secondary template: %v", err)
	}
	zd, ok := Zones.Get("cust.example.")
	if !ok {
		t.Fatal("zone not registered")
	}
	if zd.Template != "hub-out" {
		t.Errorf("template not recorded on the zone: %q", zd.Template)
	}
	if got := peerAddrs(zd.Notify); len(got) != 2 || got[0] != "192.0.2.10:53" || got[1] != "192.0.2.11:5353" {
		t.Errorf("notify targets not from the template (normalized): %v", got)
	}
	if zd.Notify[0].Key != opKey {
		t.Errorf("notify key lost: %+v", zd.Notify[0])
	}
	if len(zd.Downstreams) != 1 || zd.Downstreams[0].Key != opKey {
		t.Errorf("downstreams not from the template: %+v", zd.Downstreams)
	}
	if len(zd.DownstreamAuth) != 1 || zd.DownstreamAuth[0] != "tsig" {
		t.Errorf("downstream-auth not from the template: %v", zd.DownstreamAuth)
	}
	if len(zd.AllowNotify) != 1 {
		t.Errorf("allow-notify not from the template: %+v", zd.AllowNotify)
	}
	if zd.notifyRetries == nil || *zd.notifyRetries != 3 || zd.notifyRetryInterval != 4*time.Second {
		t.Errorf("NOTIFY resend settings not from the template: %v %v", zd.notifyRetries, zd.notifyRetryInterval)
	}

	// The template must not redirect the zone or change anything but the
	// outbound side.
	if len(zd.PrimariesConf) != 1 || zd.PrimariesConf[0].Addr != "198.51.100.1:53" {
		t.Errorf("a template must never supply primaries: %+v", zd.PrimariesConf)
	}
	if zd.Options[OptAllowUpdates] {
		t.Error("a template must not give an API secondary its options")
	}
	if len(zd.TransferSrc) != 0 {
		t.Errorf("a template must not give an API secondary its transfer-src: %v", zd.TransferSrc)
	}

	select {
	case zr := <-ch:
		if zr.Template != "hub-out" {
			t.Errorf("refresher does not carry the template: %+v", zr)
		}
	default:
		t.Error("expected a ZoneRefresher to be enqueued")
	}

	// The template is untouched by the add.
	if got := Templates["hub-out"].Notify[0].Addr; got != "192.0.2.10" {
		t.Errorf("template mutated by the add: %q", got)
	}
}

func TestProvisionDynamicSecondary_TemplateGates(t *testing.T) {
	conf, _ := newTestConfigForCores(t)
	withOpKey(t, conf)
	good := hubTemplate()
	unblessed := hubTemplate()
	unblessed.DynamicZones = false
	primaryType := hubTemplate()
	primaryType.Type = "primary"
	untyped := hubTemplate()
	untyped.Type = ""
	badKey := hubTemplate()
	badKey.Downstreams = []AclEntry{{Prefix: "192.0.2.0/24", Key: "no-such-key."}}
	badNotify := hubTemplate()
	badNotify.Notify = []PeerConf{{Addr: "192.0.2.10", Key: "no-such-key."}}
	badAuth := hubTemplate()
	badAuth.DownstreamAuth = []string{"telepathy"}
	withTestTemplates(t, map[string]ZoneConf{
		"hub-out": good, "unblessed": unblessed, "primary-type": primaryType,
		"untyped": untyped, "bad-key": badKey, "bad-notify": badNotify, "bad-auth": badAuth,
	})

	cases := []struct{ template, want string }{
		{"nope", "does not exist"},
		{"unblessed", "not blessed"},
		{"primary-type", "not secondary"},
		{"untyped", "must say type: secondary"},
		{"bad-key", "downstreams"},
		{"bad-notify", "unknown key"},
		{"bad-auth", "downstream-auth"},
	}
	for _, c := range cases {
		resetZonesForTest()
		in := secondaryIn("gate.example")
		in.Template = c.template
		_, err := conf.ProvisionDynamicZone(context.Background(), in, true)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("template %q: want an error containing %q, got %v", c.template, c.want, err)
		}
		if _, ok := Zones.Get("gate.example."); ok {
			t.Errorf("template %q: a refused add must not register the zone", c.template)
		}
	}

	// The secondary's own inline key authenticates its primaries. It is not
	// a key the template may bind its downstreams to -- also when an earlier
	// add has already put it in the keystore, which is the usual case.
	resetZonesForTest()
	const custSecret = "Y3VzdC1rZXktc2VjcmV0"
	conf.Internal.TsigKeyStore.Add(TsigDetails{Name: "cust-key.", Algorithm: "hmac-sha256", Secret: custSecret})
	inlineBound := hubTemplate()
	inlineBound.Downstreams = []AclEntry{{Prefix: "192.0.2.0/24", Key: "cust-key."}}
	Templates["inline-bound"] = inlineBound
	in := secondaryIn("inline.example")
	in.Template = "inline-bound"
	in.TsigName, in.TsigSecret = "cust-key.", custSecret
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err == nil ||
		!strings.Contains(err.Error(), "own inbound TSIG key") {
		t.Errorf("a template naming the zone's own inbound key (already in the store) must be refused for that reason: %v", err)
	}
	// The same through the zone's primaries rather than an inline key.
	in = secondaryIn("inline2.example")
	in.Primaries[0].Key = "cust-key."
	in.Template = "inline-bound"
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err == nil ||
		!strings.Contains(err.Error(), "own inbound TSIG key") {
		t.Errorf("a template naming the key the zone's primaries use must be refused: %v", err)
	}
	// An operator key declared in keys.tsig may serve both directions.
	conf.Keys.Tsig = []TsigDetails{{Name: opKey}}
	t.Cleanup(func() { conf.Keys.Tsig = nil })
	in = secondaryIn("opkey.example")
	in.Primaries[0].Key = opKey
	in.Template = "hub-out"
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Errorf("an operator key from keys.tsig, used both inbound and in the template, must be accepted: %v", err)
	}
}

func TestInboundKeyInTemplateOnModifyAndReload(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	withOpKey(t, conf)
	conf.Internal.TsigKeyStore.Add(TsigDetails{Name: "cust-key.", Algorithm: "hmac-sha256", Secret: "Y3VzdC1rZXktc2VjcmV0"})
	bad := hubTemplate()
	bad.Notify = []PeerConf{{Addr: "192.0.2.10", Key: "cust-key."}}
	withTestTemplates(t, map[string]ZoneConf{"hub-out": hubTemplate(), "bad": bad})
	ctx := context.Background()

	in := secondaryIn("k.example")
	in.Primaries[0].Key = "cust-key."
	in.Template = "hub-out"
	if _, err := conf.ProvisionDynamicZone(ctx, in, true); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := conf.ModifyDynamicZone(ctx, DynamicZoneInput{Name: "k.example", Template: "bad"}); err == nil ||
		!strings.Contains(err.Error(), "own inbound TSIG key") {
		t.Errorf("modify onto a template naming the zone's inbound key must be refused: %v", err)
	}
	// The zone's template is edited to name its inbound key: the reload
	// keeps what the zone had and warns.
	Templates["hub-out"] = bad
	if res := conf.ReapplyDynamicZoneTemplates(); res.Failed != 1 {
		t.Errorf("reload with a template naming the zone's inbound key: %+v", res)
	}
	zd, _ := Zones.Get("k.example.")
	if _, has := zd.Errors[TemplateWarning]; !has {
		t.Error("expected a TemplateWarning")
	}
	if len(zd.Notify) != 2 || zd.Notify[0].Key != opKey {
		t.Errorf("the zone must keep its previous NOTIFY targets: %+v", zd.Notify)
	}
}

func TestProvisionDynamicZone_DefaultTemplate(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	withOpKey(t, conf)
	other := hubTemplate()
	other.Name = "other-out"
	other.Notify = []PeerConf{{Addr: "192.0.2.20", Key: opKey}}
	dir := t.TempDir()
	withTestTemplates(t, map[string]ZoneConf{
		"hub-out": hubTemplate(), "other-out": other, "dyn-test": dynPrimaryTestTemplate(dir),
	})
	conf.DynamicZones.Dynamic.DefaultTemplate = map[string]string{"secondary": "hub-out", "primary": "dyn-test"}

	// No template named: the default for the type applies, and is recorded.
	if _, err := conf.ProvisionDynamicZone(context.Background(), secondaryIn("dflt.example"), true); err != nil {
		t.Fatalf("add with the default template: %v", err)
	}
	zd, _ := Zones.Get("dflt.example.")
	if zd.Template != "hub-out" || len(zd.Downstreams) != 1 {
		t.Errorf("default template not applied: template %q downstreams %+v", zd.Template, zd.Downstreams)
	}

	// A named template wins over the default.
	in := secondaryIn("named.example")
	in.Template = "other-out"
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("add naming a template: %v", err)
	}
	zd, _ = Zones.Get("named.example.")
	if zd.Template != "other-out" || peerAddrs(zd.Notify)[0] != "192.0.2.20:53" {
		t.Errorf("named template did not win: %q %v", zd.Template, peerAddrs(zd.Notify))
	}

	// A primary with no template takes the primary default.
	if _, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{Name: "prim.example", Type: Primary}, true); err != nil {
		t.Fatalf("primary add with the default template: %v", err)
	}
	zd, _ = Zones.Get("prim.example.")
	if zd.Template != "dyn-test" {
		t.Errorf("primary default template not applied: %q", zd.Template)
	}

	// The catalog path (fromAPI=false) never takes the API default.
	if _, err := conf.ProvisionDynamicZone(context.Background(), secondaryIn("member.example"), false); err != nil {
		t.Fatalf("catalog-path add: %v", err)
	}
	zd, _ = Zones.Get("member.example.")
	if zd.Template != "" || len(zd.Downstreams) != 0 {
		t.Errorf("the API default must not reach catalog-provisioned zones: %q %+v", zd.Template, zd.Downstreams)
	}
}

func TestDynamicZonesConf_DefaultTemplateValidation(t *testing.T) {
	good := hubTemplate()
	unblessed := hubTemplate()
	unblessed.Name, unblessed.DynamicZones = "unblessed", false
	parent := ZoneConf{Name: "base", Type: "secondary"}
	child := hubTemplate()
	child.Name, child.Type, child.Template = "child", "", "base"
	prim := ZoneConf{Name: "prim", Type: "primary", DynamicZones: true}
	// Declares its own type, but its parent is missing: buildTemplateMap
	// drops it, so a default naming it would fail every add.
	orphan := hubTemplate()
	orphan.Name, orphan.Template = "orphan", "no-such-parent"
	loopA := hubTemplate()
	loopA.Name, loopA.Template = "loop-a", "loop-b"
	loopB := ZoneConf{Name: "loop-b", Type: "secondary", Template: "loop-a"}
	templates := []ZoneConf{good, unblessed, parent, child, prim, orphan, loopA, loopB}

	cases := []struct {
		dflt map[string]string
		want string // "" means valid
	}{
		{map[string]string{"secondary": "hub-out"}, ""},
		{map[string]string{"Secondary": "hub-out", "primary": "prim"}, ""},
		{map[string]string{"secondary": "child"}, ""}, // type inherited from its parent template
		{map[string]string{"secondary": "nope"}, "does not exist"},
		{map[string]string{"secondary": "unblessed"}, "not blessed"},
		{map[string]string{"secondary": "prim"}, "not secondary"},
		{map[string]string{"primary": "hub-out"}, "not primary"},
		{map[string]string{"secondary": " "}, "empty template name"},
		{map[string]string{"secondary": "orphan"}, "does not exist"},
		{map[string]string{"secondary": "loop-a"}, "cycle"},
	}
	for _, c := range cases {
		d := DynamicZonesConf{Dynamic: DynamicApiZoneConf{DefaultTemplate: c.dflt}}
		err := d.ValidateDefaultTemplates(templates)
		if c.want == "" && err != nil {
			t.Errorf("%v: want valid, got %v", c.dflt, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%v: want an error containing %q, got %v", c.dflt, c.want, err)
		}
	}

	d := DynamicZonesConf{Dynamic: DynamicApiZoneConf{DefaultTemplate: map[string]string{"forwarder": "hub-out"}}}
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "unknown zone type") {
		t.Errorf("an unknown zone type key must be refused: %v", err)
	}
}

func TestZoneDataToZoneConf_TemplateOwnsOutbound(t *testing.T) {
	outbound := func(zd *ZoneData) {
		zd.Notify = []PeerConf{{Addr: "192.0.2.10:53", Key: opKey}}
		zd.Downstreams = []AclEntry{{Prefix: "192.0.2.0/24", Key: opKey}}
		zd.AllowNotify = []AclEntry{{Prefix: "198.51.100.1/32", Key: NOKEY}}
		zd.DownstreamAuth = []string{"tsig"}
	}
	api := map[ZoneOption]bool{OptApiManagedZone: true}

	templated := &ZoneData{ZoneName: "t.example.", ZoneType: Secondary, Template: "hub-out", Options: api}
	outbound(templated)
	zc := zoneDataToZoneConf(templated, "/tmp")
	if zc.Template != "hub-out" {
		t.Errorf("template name must be persisted: %q", zc.Template)
	}
	if hasTemplateOwned(&zc) {
		t.Errorf("a template-driven zone's outbound settings must not be persisted: %+v %+v %+v %v", zc.Notify, zc.Downstreams, zc.AllowNotify, zc.DownstreamAuth)
	}

	plain := &ZoneData{ZoneName: "p.example.", ZoneType: Secondary, Options: api}
	outbound(plain)
	zc = zoneDataToZoneConf(plain, "/tmp")
	if len(zc.Notify) != 1 || len(zc.Downstreams) != 1 {
		t.Errorf("a zone without a template keeps persisting its outbound settings: %+v", zc)
	}

	prim := &ZoneData{ZoneName: "k.example.", ZoneType: Primary, Template: "dyn-test", InlineTsigKey: "zone-key.", Options: api}
	outbound(prim)
	zc = zoneDataToZoneConf(prim, "/tmp")
	if hasTemplateOwned(&zc) || zc.InlineTsigKey != "zone-key." {
		t.Errorf("a template-driven primary persists its inline key in place of the outbound lists: key %q, %+v", zc.InlineTsigKey, zc.Downstreams)
	}

	shell := &ZoneData{ZoneName: "s.example.", ZoneType: Primary, Template: "gone", Options: api, keepPersistedOutbound: true}
	outbound(shell)
	zc = zoneDataToZoneConf(shell, "/tmp")
	if len(zc.Downstreams) != 1 {
		t.Error("an error-state shell of a legacy entry must write its outbound settings back unchanged")
	}
}

func TestLoadDynamicZoneFiles_SecondaryTemplate(t *testing.T) {
	resetZonesForTest()
	conf, ch := newTestConfigForCores(t)
	withOpKey(t, conf)
	withTestTemplates(t, map[string]ZoneConf{"hub-out": hubTemplate()})
	dir := t.TempDir()
	dynCfg := filepath.Join(dir, "dynamic-zones.yaml")
	// ok.example carries stale outbound lists (as if hand-edited): the
	// template replaces them, and the entry is rewritten without them.
	cfgYaml := `zones:
  - name: ok.example.
    type: secondary
    store: map
    template: hub-out
    apimanaged: true
    primaries:
      - addr: 198.51.100.1:53
        key: NOKEY
    downstreams:
      - prefix: 0.0.0.0/0
        key: NOKEY
  - name: broken.example.
    type: secondary
    store: map
    template: gone-template
    apimanaged: true
    primaries:
      - addr: 198.51.100.1:53
        key: NOKEY
`
	if err := os.WriteFile(dynCfg, []byte(cfgYaml), 0644); err != nil {
		t.Fatal(err)
	}
	conf.DynamicZones.ConfigFile = dynCfg
	conf.DynamicZones.ZoneDirectory = dir

	if err := conf.LoadDynamicZoneFiles(context.Background()); err != nil {
		t.Fatalf("LoadDynamicZoneFiles: %v", err)
	}

	got := map[string]ZoneRefresher{}
	for len(ch) > 0 {
		zr := <-ch
		got[zr.Name] = zr
	}
	ok, found := got["ok.example."]
	if !found {
		t.Fatal("ok.example. not enqueued")
	}
	if ok.Template != "hub-out" || !ok.ConfigUpdate {
		t.Errorf("refresher lost the template: %+v", ok)
	}
	if len(ok.Downstreams) != 1 || ok.Downstreams[0].Prefix != "192.0.2.0/24" || ok.Downstreams[0].Key != opKey {
		t.Errorf("the template must replace persisted downstreams: %+v", ok.Downstreams)
	}
	if len(ok.Notify) != 2 || ok.NotifyRetries == nil || *ok.NotifyRetries != 3 {
		t.Errorf("notify settings not from the template: %+v %v", ok.Notify, ok.NotifyRetries)
	}
	if ok.TemplateWarning != "" {
		t.Errorf("unexpected template warning: %q", ok.TemplateWarning)
	}

	broken, found := got["broken.example."]
	if !found {
		t.Fatal("a secondary whose template is missing must still load (it serves without its outbound settings)")
	}
	if len(broken.Downstreams) != 0 || len(broken.Notify) != 0 {
		t.Errorf("no template, no outbound settings: %+v %+v", broken.Downstreams, broken.Notify)
	}
	if !strings.Contains(broken.TemplateWarning, "does not exist") || broken.Template != "gone-template" {
		t.Errorf("broken template must travel as a warning and keep its name: %q %q", broken.TemplateWarning, broken.Template)
	}

	// The stale lists were stripped from the file.
	data, err := os.ReadFile(dynCfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "0.0.0.0/0") {
		t.Errorf("the entry was not rewritten without its stale outbound lists:\n%s", data)
	}
}

func TestReapplyDynamicZoneTemplates(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	withOpKey(t, conf)
	dir := t.TempDir()
	prim := dynPrimaryTestTemplate(dir)
	withTestTemplates(t, map[string]ZoneConf{"hub-out": hubTemplate(), "dyn-test": prim})

	in := secondaryIn("r.example")
	in.Template = "hub-out"
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := conf.ProvisionDynamicZone(context.Background(), secondaryIn("plain.example"), true); err != nil {
		t.Fatalf("add: %v", err)
	}
	pin := DynamicZoneInput{Name: "rp.example", Type: Primary, Template: "dyn-test", TsigName: "rp-key.", TsigSecret: "cnAta2V5LXNlY3JldA=="}
	if _, err := conf.ProvisionDynamicZone(context.Background(), pin, true); err != nil {
		t.Fatalf("primary add: %v", err)
	}

	// The operator adds a downstream site to both templates and reloads.
	edited := hubTemplate()
	edited.Notify = append(edited.Notify, PeerConf{Addr: "192.0.2.12", Key: opKey})
	edited.Downstreams = append(edited.Downstreams, AclEntry{Prefix: "203.0.113.0/24", Key: opKey})
	editedPrim := prim
	editedPrim.Downstreams = []AclEntry{{Prefix: "127.0.0.1/32", Key: NOKEY}, {Prefix: "10.0.0.0/8", Key: NOKEY}}
	Templates["hub-out"], Templates["dyn-test"] = edited, editedPrim

	res := conf.ReapplyDynamicZoneTemplates()
	if res.Zones != 2 || res.Changed != 2 || res.Failed != 0 {
		t.Errorf("reapply counts: %+v (want 2 zones, 2 changed)", res)
	}
	zd, _ := Zones.Get("r.example.")
	if len(zd.Notify) != 3 || len(zd.Downstreams) != 2 {
		t.Errorf("the edited template did not reach the secondary: %v %+v", peerAddrs(zd.Notify), zd.Downstreams)
	}
	pzd, _ := Zones.Get("rp.example.")
	if len(pzd.Downstreams) != 2 || pzd.Downstreams[1].Key != "rp-key." {
		t.Errorf("the edited template did not reach the primary, or lost its inline key binding: %+v", pzd.Downstreams)
	}
	plain, _ := Zones.Get("plain.example.")
	if len(plain.Downstreams) != 0 {
		t.Errorf("a zone without a template must not be touched: %+v", plain.Downstreams)
	}

	// Nothing changed: a second reload reports no change.
	if res := conf.ReapplyDynamicZoneTemplates(); res.Changed != 0 {
		t.Errorf("an unchanged template must report no change: %+v", res)
	}

	// The template breaks: the zone keeps what it had, with a warning.
	delete(Templates, "hub-out")
	res = conf.ReapplyDynamicZoneTemplates()
	if res.Failed != 1 {
		t.Errorf("reapply counts with a missing template: %+v", res)
	}
	zd, _ = Zones.Get("r.example.")
	if len(zd.Notify) != 3 || len(zd.Downstreams) != 2 {
		t.Errorf("a broken template must not cut a live zone off from its downstreams: %v %+v", peerAddrs(zd.Notify), zd.Downstreams)
	}
	if _, has := zd.Errors[TemplateWarning]; !has {
		t.Error("a broken template must leave a TemplateWarning")
	}
	if zd.HasServiceImpactingError() {
		t.Error("a TemplateWarning must not stop the zone from serving")
	}

	// Fixed: the warning clears.
	Templates["hub-out"] = hubTemplate()
	conf.ReapplyDynamicZoneTemplates()
	zd, _ = Zones.Get("r.example.")
	if _, has := zd.Errors[TemplateWarning]; has {
		t.Error("a successful expansion must clear the TemplateWarning")
	}
	if len(zd.Notify) != 2 {
		t.Errorf("restored template not applied: %v", peerAddrs(zd.Notify))
	}
}

func TestModifyDynamicZone_TemplateKeepSetClear(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	withOpKey(t, conf)
	unblessed := hubTemplate()
	unblessed.DynamicZones = false
	withTestTemplates(t, map[string]ZoneConf{"hub-out": hubTemplate(), "unblessed": unblessed})
	ctx := context.Background()

	if _, err := conf.ProvisionDynamicZone(ctx, secondaryIn("m.example"), true); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Set a template on a zone that had none (moving existing zones onto it).
	if _, err := conf.ModifyDynamicZone(ctx, DynamicZoneInput{Name: "m.example", Template: "hub-out"}); err != nil {
		t.Fatalf("modify --template: %v", err)
	}
	zd, _ := Zones.Get("m.example.")
	if zd.Template != "hub-out" || len(zd.Downstreams) != 1 || len(zd.Notify) != 2 {
		t.Errorf("set template: %q %+v %v", zd.Template, zd.Downstreams, peerAddrs(zd.Notify))
	}

	// A modify that says nothing about the template keeps it.
	if _, err := conf.ModifyDynamicZone(ctx, DynamicZoneInput{Name: "m.example", Primaries: []PeerConf{{Addr: "198.51.100.2:53", Key: NOKEY}}}); err != nil {
		t.Fatalf("modify primaries: %v", err)
	}
	zd, _ = Zones.Get("m.example.")
	if zd.Template != "hub-out" || len(zd.Downstreams) != 1 || zd.PrimariesConf[0].Addr != "198.51.100.2:53" {
		t.Errorf("an unrelated modify must keep the template: %q %+v %+v", zd.Template, zd.Downstreams, zd.PrimariesConf)
	}
	if zd.notifyRetries == nil || *zd.notifyRetries != 3 {
		t.Errorf("an unrelated modify must keep the template's NOTIFY resend settings: %v", zd.notifyRetries)
	}

	// Refusals leave the zone as it was.
	if _, err := conf.ModifyDynamicZone(ctx, DynamicZoneInput{Name: "m.example", Template: "unblessed"}); err == nil {
		t.Error("modify to an unblessed template must be refused")
	}
	if _, err := conf.ModifyDynamicZone(ctx, DynamicZoneInput{Name: "m.example", Template: "hub-out", ClearTemplate: true}); err == nil {
		t.Error("set and clear together must be refused")
	}
	zd, _ = Zones.Get("m.example.")
	if zd.Template != "hub-out" {
		t.Errorf("a refused modify changed the template: %q", zd.Template)
	}

	// The template goes missing: an unrelated modify still works, keeps the
	// outbound settings, and warns.
	delete(Templates, "hub-out")
	if _, err := conf.ModifyDynamicZone(ctx, DynamicZoneInput{Name: "m.example", Primaries: []PeerConf{{Addr: "198.51.100.3:53", Key: NOKEY}}}); err != nil {
		t.Fatalf("modify with the zone's template missing: %v", err)
	}
	zd, _ = Zones.Get("m.example.")
	if len(zd.Downstreams) != 1 {
		t.Errorf("outbound settings lost on modify with a missing template: %+v", zd.Downstreams)
	}
	if _, has := zd.Errors[TemplateWarning]; !has {
		t.Error("missing template on modify must leave a TemplateWarning")
	}
	Templates["hub-out"] = hubTemplate()

	// Clear the template: its outbound settings go with it.
	if _, err := conf.ModifyDynamicZone(ctx, DynamicZoneInput{Name: "m.example", ClearTemplate: true}); err != nil {
		t.Fatalf("modify --clear-template: %v", err)
	}
	zd, _ = Zones.Get("m.example.")
	if zd.Template != "" || len(zd.Downstreams) != 0 || len(zd.Notify) != 0 || zd.notifyRetries != nil {
		t.Errorf("clear template must clear what the template gave: %q %+v %v %v", zd.Template, zd.Downstreams, peerAddrs(zd.Notify), zd.notifyRetries)
	}
}

func TestLegacyInlineTsigKey(t *testing.T) {
	tmpl := []AclEntry{
		{Prefix: "127.0.0.1/32", Key: NOKEY},
		{Prefix: "192.0.2.0/24", Key: "fixed-key."},
		{Prefix: "198.51.100.0/24", Key: "BLOCKED"},
	}
	cases := []struct {
		name      string
		persisted []AclEntry
		want      string
		wantErr   bool
	}{
		{"rewired", []AclEntry{{Prefix: "127.0.0.1/32", Key: "zone-key."}, {Prefix: "192.0.2.0/24", Key: "fixed-key."}}, "zone-key.", false},
		{"no inline key", []AclEntry{{Prefix: "127.0.0.1/32", Key: NOKEY}, {Prefix: "192.0.2.0/24", Key: "fixed-key."}}, "", false},
		// The template's keyed entry changed key since: not a keyless
		// prefix, so it does not count.
		{"template key changed", []AclEntry{{Prefix: "127.0.0.1/32", Key: "zone-key."}, {Prefix: "192.0.2.0/24", Key: "old-key."}}, "zone-key.", false},
		{"ambiguous", []AclEntry{{Prefix: "127.0.0.1/32", Key: "zone-key."}, {Prefix: "127.0.0.1/32", Key: "other-key."}}, "", true},
		{"nothing persisted", nil, "", false},
		// The inline key sat on a prefix the template has since dropped,
		// and the template's keyless prefix is new: no evidence either way.
		{"keyed prefix dropped, keyless prefix new", []AclEntry{{Prefix: "203.0.113.0/24", Key: "zone-key."}, {Prefix: "192.0.2.0/24", Key: "fixed-key."}}, "", true},
		// The same, but the entry shows the keyless prefix left keyless:
		// there was no inline key.
		{"keyed prefix dropped, keyless prefix shown keyless", []AclEntry{{Prefix: "203.0.113.0/24", Key: "gone-key."}, {Prefix: "127.0.0.1/32", Key: NOKEY}}, "", false},
	}
	for _, c := range cases {
		got, err := legacyInlineTsigKey(tmpl, c.persisted)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%s: got %q, %v; want %q, error %v", c.name, got, err, c.want, c.wantErr)
		}
	}
}

func TestPrepareDynamicPrimary_TemplateOwnsOutbound(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	withOpKey(t, conf)
	dir := t.TempDir()
	tmpl := dynPrimaryTestTemplate(dir)
	tmpl.Downstreams = []AclEntry{{Prefix: "127.0.0.1/32", Key: NOKEY}, {Prefix: "10.0.0.0/8", Key: NOKEY}}
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": tmpl})

	// Current form: the persisted entry has the inline key and no lists;
	// every keyless template entry, including one added since, is bound to
	// the key.
	spec, err := conf.prepareDynamicPrimary(ZoneConf{Name: "cur.example", Template: "dyn-test", InlineTsigKey: opKey}, nil, false)
	if err != nil {
		t.Fatalf("current-form entry: %v", err)
	}
	if spec.LegacyEntry || spec.InlineTsigKey != opKey || len(spec.Zconf.Downstreams) != 2 ||
		spec.Zconf.Downstreams[0].Key != opKey || spec.Zconf.Downstreams[1].Key != opKey {
		t.Errorf("current form: legacy %v key %q downstreams %+v", spec.LegacyEntry, spec.InlineTsigKey, spec.Zconf.Downstreams)
	}

	// Legacy form: materialized lists, rewired to the key, from a template
	// that had only the 127.0.0.1 entry. The lists are replaced by the
	// template's, the key is recovered and bound to the new entry too.
	legacy := ZoneConf{
		Name:        "old.example",
		Template:    "dyn-test",
		Downstreams: []AclEntry{{Prefix: "127.0.0.1/32", Key: opKey}},
		Notify:      []PeerConf{{Addr: "192.0.2.99:53", Key: NOKEY}},
	}
	spec, err = conf.prepareDynamicPrimary(legacy, nil, false)
	if err != nil {
		t.Fatalf("legacy entry: %v", err)
	}
	if !spec.LegacyEntry || spec.InlineTsigKey != opKey {
		t.Errorf("legacy entry: legacy %v key %q", spec.LegacyEntry, spec.InlineTsigKey)
	}
	if len(spec.Zconf.Downstreams) != 2 || spec.Zconf.Downstreams[1].Key != opKey {
		t.Errorf("legacy entry: template lists not applied with the recovered key: %+v", spec.Zconf.Downstreams)
	}
	if len(spec.Zconf.Notify) != 0 {
		t.Errorf("legacy entry: persisted notify must give way to the template's (none): %+v", spec.Zconf.Notify)
	}

	// Ambiguous legacy entry: refused (the boot path puts it in error state)
	// rather than guessing a key and maybe opening the zone.
	amb := legacy
	amb.Downstreams = []AclEntry{{Prefix: "127.0.0.1/32", Key: opKey}, {Prefix: "10.0.0.0/8", Key: "other-key."}}
	if _, err := conf.prepareDynamicPrimary(amb, nil, false); err == nil || !strings.Contains(err.Error(), "inline-tsig-key") {
		t.Errorf("ambiguous legacy entry: %v", err)
	}
}

func TestLoadDynamicZoneFiles_LegacyPrimaryEntry(t *testing.T) {
	resetZonesForTest()
	conf, ch := newTestConfigForCores(t)
	withOpKey(t, conf)
	dir := t.TempDir()
	tmpl := dynPrimaryTestTemplate(dir)
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": tmpl})
	for _, z := range []string{"old.example", "amb.example"} {
		zf := filepath.Join(dir, z+".zone")
		if err := os.WriteFile(zf, []byte(z+".\t3600\tIN\tSOA\tns."+z+". h."+z+". 1 3600 600 604800 300\n"+z+".\t3600\tIN\tNS\tns."+z+".\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	dynCfg := filepath.Join(dir, "dynamic-zones.yaml")
	cfgYaml := `zones:
  - name: old.example.
    type: primary
    store: map
    template: dyn-test
    zonefile: ` + filepath.Join(dir, "old.example.zone") + `
    apimanaged: true
    downstreams:
      - prefix: 127.0.0.1/32
        key: op-key.
  - name: amb.example.
    type: primary
    store: map
    template: dyn-test
    zonefile: ` + filepath.Join(dir, "amb.example.zone") + `
    apimanaged: true
    downstreams:
      - prefix: 127.0.0.1/32
        key: op-key.
      - prefix: 127.0.0.1/32
        key: second-key.
`
	if err := os.WriteFile(dynCfg, []byte(cfgYaml), 0644); err != nil {
		t.Fatal(err)
	}
	conf.DynamicZones.ConfigFile = dynCfg
	conf.DynamicZones.ZoneDirectory = dir
	conf.DynamicZones.Dynamic.Storage = "persistent"

	if err := conf.LoadDynamicZoneFiles(context.Background()); err != nil {
		t.Fatalf("LoadDynamicZoneFiles: %v", err)
	}

	select {
	case zr := <-ch:
		if zr.Name != "old.example." || zr.InlineTsigKey != opKey {
			t.Errorf("legacy entry: refresher %s, inline key %q", zr.Name, zr.InlineTsigKey)
		}
		if len(zr.Downstreams) != 1 || zr.Downstreams[0].Key != opKey {
			t.Errorf("legacy entry: recovered key not bound to the template's keyless entry: %+v", zr.Downstreams)
		}
	default:
		t.Fatal("old.example. not enqueued")
	}

	// The ambiguous entry is an error-state shell that keeps its lists.
	zd, ok := Zones.Get("amb.example.")
	if !ok || !zd.Error || !zd.keepPersistedOutbound || len(zd.Downstreams) != 2 {
		t.Fatalf("ambiguous legacy entry must be an error shell keeping its lists: %+v", zd)
	}

	// The file: old.example in the current form; amb.example untouched.
	data, err := os.ReadFile(dynCfg)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, "inline-tsig-key: op-key.") {
		t.Errorf("legacy entry not re-persisted with its inline key:\n%s", out)
	}
	if !strings.Contains(out, "second-key.") {
		t.Errorf("the ambiguous entry's lists must survive the rewrite:\n%s", out)
	}
	// A later rewrite from live state keeps the shell's lists too.
	if err := conf.WriteDynamicConfigFile(); err != nil {
		t.Fatalf("WriteDynamicConfigFile: %v", err)
	}
	data, _ = os.ReadFile(dynCfg)
	if !strings.Contains(string(data), "second-key.") {
		t.Errorf("a rewrite from live state lost the error shell's lists:\n%s", data)
	}
}

func TestReapplySkipsLegacyErrorShell(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	withOpKey(t, conf)
	dir := t.TempDir()
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": dynPrimaryTestTemplate(dir)})
	kept := []AclEntry{{Prefix: "127.0.0.1/32", Key: opKey}}
	shell := &ZoneData{
		ZoneName: "shell.example.", ZoneType: Primary, Template: "dyn-test",
		Options:               map[ZoneOption]bool{OptApiManagedZone: true},
		Downstreams:           kept,
		keepPersistedOutbound: true,
	}
	Zones.Set("shell.example.", shell)
	if res := conf.ReapplyDynamicZoneTemplates(); res.Zones != 0 {
		t.Errorf("a legacy error shell must not be re-expanded: %+v", res)
	}
	if len(shell.Downstreams) != 1 || shell.Downstreams[0].Key != opKey {
		t.Errorf("the shell's kept downstreams were replaced: %+v", shell.Downstreams)
	}
}

func TestTemplateWarningDoesNotBlockSerialBump(t *testing.T) {
	zd := &ZoneData{ZoneName: "bump.example."}
	Zones.Set("bump.example.", zd)
	t.Cleanup(func() { Zones.Remove("bump.example.") })
	zd.SetError(TemplateWarning, "template gone")
	if zd.blocksSerialBump() {
		t.Error("a TemplateWarning alone must not block a serial bump")
	}
	zd.SetError(ConfigWarning, "something else")
	if !zd.blocksSerialBump() {
		t.Error("any other error must still block a serial bump")
	}
}

func TestReloadTemplatesNormalizesTransferAliases(t *testing.T) {
	savedTemplates, savedApp := Templates, Globals.App.Type
	t.Cleanup(func() { Templates, Globals.App.Type = savedTemplates, savedApp })
	Globals.App.Type = AppTypeAuth
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tdns-auth.yaml")
	if err := os.WriteFile(cfg, []byte(`templates:
   - name: hub-out
     type: secondary
     dynamiczones: true
     provide-xfr:
        - prefix: "192.0.2.0/24"
          key: op-key.
`), 0644); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.CfgFile = cfg
	if err := conf.reloadTemplatesFromFile(); err != nil {
		t.Fatalf("reloadTemplatesFromFile: %v", err)
	}
	if got := Templates["hub-out"].Downstreams; len(got) != 1 || got[0].Prefix != "192.0.2.0/24" {
		t.Errorf("a template's provide-xfr: must decode as its downstreams on reload: %+v", got)
	}
}
