package tdns

import "testing"

// Per-zone outbound-soa-serial (design doc §5). The mode used to be
// server-global; these tests pin the tier resolution (zone -> global ->
// "keep"), the template interaction, and the persistence round-trip.

// TestEffectiveOutboundSoaSerialTiers pins the resolution order of
// zd.EffectiveOutboundSoaSerial(): an explicit per-zone value wins, an empty
// one falls through to the server-global setting on the KeyDB, and with
// neither set the documented default ("keep") applies.
func TestEffectiveOutboundSoaSerialTiers(t *testing.T) {
	tests := []struct {
		name   string
		zone   string // zd.OutboundSoaSerial (per-zone)
		global string // kdb.OutboundSoaSerial (server-global)
		want   string
	}{
		{"zone wins over global", OutboundSoaSerialPersist, OutboundSoaSerialKeep, OutboundSoaSerialPersist},
		{"zone keep beats global persist", OutboundSoaSerialKeep, OutboundSoaSerialPersist, OutboundSoaSerialKeep},
		{"empty zone inherits global", "", OutboundSoaSerialUnixtime, OutboundSoaSerialUnixtime},
		{"empty zone inherits global persist", "", OutboundSoaSerialPersist, OutboundSoaSerialPersist},
		{"neither set defaults to keep", "", "", OutboundSoaSerialKeep},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kdb := &KeyDB{}
			kdb.SetOutboundSoaSerial(tc.global)
			zd := &ZoneData{
				ZoneName:          "example.",
				OutboundSoaSerial: tc.zone,
				KeyDB:             kdb,
			}
			if got := zd.EffectiveOutboundSoaSerial(); got != tc.want {
				t.Errorf("EffectiveOutboundSoaSerial() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEffectiveOutboundSoaSerialNilKeyDB guards the nil-KeyDB case: several
// unit-test and early-init paths build a ZoneData with no KeyDB, and the
// resolver must not panic there.
func TestEffectiveOutboundSoaSerialNilKeyDB(t *testing.T) {
	zd := &ZoneData{ZoneName: "example."}
	if got := zd.EffectiveOutboundSoaSerial(); got != OutboundSoaSerialKeep {
		t.Errorf("nil KeyDB: got %q, want %q", got, OutboundSoaSerialKeep)
	}

	zd.OutboundSoaSerial = OutboundSoaSerialUnixtime
	if got := zd.EffectiveOutboundSoaSerial(); got != OutboundSoaSerialUnixtime {
		t.Errorf("nil KeyDB with per-zone value: got %q, want %q", got, OutboundSoaSerialUnixtime)
	}
}

// TestNextOutboundSerialUsesPerZoneMode pins that the serial arithmetic reads
// the EFFECTIVE mode, not the global one: a zone in unixtime mode jumps to a
// timestamp even when the server-global default is keep, and a zone that
// explicitly says keep stays on prev+1 under a unixtime global.
func TestNextOutboundSerialUsesPerZoneMode(t *testing.T) {
	// Per-zone unixtime under a global keep: must jump far past prev+1.
	zd := &ZoneData{
		ZoneName:          "example.",
		CurrentSerial:     10,
		OutboundSoaSerial: OutboundSoaSerialUnixtime,
		KeyDB:             kdbWithSoaSerial(OutboundSoaSerialKeep),
	}
	if got := nextOutboundSerial(zd); got <= 11 {
		t.Errorf("per-zone unixtime: got %d, want a unix timestamp (>> 11)", got)
	}

	// Per-zone keep under a global unixtime: must be plain prev+1.
	zd = &ZoneData{
		ZoneName:          "example.",
		CurrentSerial:     10,
		OutboundSoaSerial: OutboundSoaSerialKeep,
		KeyDB:             kdbWithSoaSerial(OutboundSoaSerialUnixtime),
	}
	if got := nextOutboundSerial(zd); got != 11 {
		t.Errorf("per-zone keep: got %d, want 11", got)
	}
}

// TestExpandTemplateOutboundSoaSerial covers the template interaction, which is
// the intended granularity for this setting: a template value fills a zone that
// is silent, and an explicit zone value wins. The second case is the one worth
// pinning — ExpandTemplate's gap-fill treats "already set" as "non-zero", so an
// explicit "keep" under a "persist" template survives only because the field is
// a string rather than a bool.
func TestExpandTemplateOutboundSoaSerial(t *testing.T) {
	tmpl := &ZoneConf{Type: "secondary", OutboundSoaSerial: OutboundSoaSerialPersist}

	// Zone silent -> inherits the template's mode.
	z, err := ExpandTemplate(ZoneConf{Name: "a.example"}, tmpl, AppTypeAuth)
	if err != nil {
		t.Fatalf("ExpandTemplate: %v", err)
	}
	if z.OutboundSoaSerial != OutboundSoaSerialPersist {
		t.Errorf("gap-fill: got %q, want %q", z.OutboundSoaSerial, OutboundSoaSerialPersist)
	}

	// Zone explicit -> wins, including the "keep beats persist" direction.
	z, err = ExpandTemplate(
		ZoneConf{Name: "b.example", OutboundSoaSerial: OutboundSoaSerialKeep}, tmpl, AppTypeAuth)
	if err != nil {
		t.Fatalf("ExpandTemplate: %v", err)
	}
	if z.OutboundSoaSerial != OutboundSoaSerialKeep {
		t.Errorf("explicit zone value: got %q, want %q", z.OutboundSoaSerial, OutboundSoaSerialKeep)
	}

	// Template silent -> zone keeps its empty value (inherit-global), rather
	// than acquiring some default from the expansion.
	z, err = ExpandTemplate(ZoneConf{Name: "c.example"}, &ZoneConf{Type: "secondary"}, AppTypeAuth)
	if err != nil {
		t.Fatalf("ExpandTemplate: %v", err)
	}
	if z.OutboundSoaSerial != "" {
		t.Errorf("both silent: got %q, want empty (inherit global)", z.OutboundSoaSerial)
	}
}

// TestZoneDataToZoneConfOutboundSoaSerial pins the dynamic-zone persistence
// round-trip. The dynamic config file is REGENERATED from live state on every
// successful refresh, so a field the serializer drops is silently lost from the
// operator's persisted config.
func TestZoneDataToZoneConfOutboundSoaSerial(t *testing.T) {
	zd := &ZoneData{
		ZoneName:          "dyn.example.",
		ZoneType:          Secondary,
		ZoneStore:         MapZone,
		Options:           map[ZoneOption]bool{},
		OutboundSoaSerial: OutboundSoaSerialPersist,
	}
	if got := zoneDataToZoneConf(zd, "/tmp/zones").OutboundSoaSerial; got != OutboundSoaSerialPersist {
		t.Errorf("serialized OutboundSoaSerial = %q, want %q", got, OutboundSoaSerialPersist)
	}

	// An unset mode must serialize as empty (inherit-global), NOT as a
	// materialized "keep" — otherwise a zone that merely inherits the global
	// would get pinned to keep the first time its config is rewritten.
	zd.OutboundSoaSerial = ""
	if got := zoneDataToZoneConf(zd, "/tmp/zones").OutboundSoaSerial; got != "" {
		t.Errorf("unset OutboundSoaSerial serialized as %q, want empty", got)
	}
}

// kdbWithSoaSerial builds a KeyDB carrying a server-global outbound serial mode.
// The field is unexported (behind an atomic.Pointer, so a config reload cannot
// race a serving goroutine), so tests set it through the accessor.
func kdbWithSoaSerial(mode string) *KeyDB {
	kdb := &KeyDB{}
	kdb.SetOutboundSoaSerial(mode)
	return kdb
}
