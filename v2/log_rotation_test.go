package tdns

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// A log: section that sets no rotation keeps the rotation every daemon had
// before #974: 20 MB, 3 rotated files, 14 days.
func TestALogSectionWithoutRotationKeysKeepsTodaysRotation(t *testing.T) {
	lc, err := parseLogConfFromFile(writeCfg(t, "log:\n   file: /var/log/tdns/x.log\n   level: info\n"))
	if err != nil {
		t.Fatalf("parseLogConfFromFile: %v", err)
	}
	lj := lc.rotatingWriter("/var/log/tdns/x.log")
	if lj.MaxSize != 20 || lj.MaxBackups != 3 || lj.MaxAge != 14 {
		t.Errorf("rotation = %d MB, %d backups, %d days; want 20, 3, 14", lj.MaxSize, lj.MaxBackups, lj.MaxAge)
	}
	if lj.Filename != "/var/log/tdns/x.log" {
		t.Errorf("file = %q, want /var/log/tdns/x.log", lj.Filename)
	}
}

// The three keys are read by the early parse (SetupLogging), by the daemon's
// decoder (ParseConfig, config check) and by viper.Unmarshal (the CLI
// roots), and a key not set keeps its default.
func TestTheLogRotationKeysAreRead(t *testing.T) {
	cfg := writeCfg(t, "log:\n   file: /var/log/tdns/x.log\n   max-size: 500\n   max-age: 30\n")

	lc, err := parseLogConfFromFile(cfg)
	if err != nil {
		t.Fatalf("parseLogConfFromFile: %v", err)
	}
	if lj := lc.rotatingWriter("f"); lj.MaxSize != 500 || lj.MaxBackups != 3 || lj.MaxAge != 30 {
		t.Errorf("early parse: rotation = %d MB, %d backups, %d days; want 500, 3 (the default), 30", lj.MaxSize, lj.MaxBackups, lj.MaxAge)
	}

	var conf Config
	md, _, _, err := decodeConfigFile(cfg, &conf)
	if err != nil {
		t.Fatalf("decodeConfigFile: %v", err)
	}
	for _, k := range md.Unused {
		if strings.HasPrefix(k, "log.") {
			t.Errorf("daemon decoder left %q unused: it would be warned about as an unknown key", k)
		}
	}
	if lj := conf.Log.rotatingWriter("f"); lj.MaxSize != 500 || lj.MaxBackups != 3 || lj.MaxAge != 30 {
		t.Errorf("daemon decoder: rotation = %d MB, %d backups, %d days; want 500, 3, 30", lj.MaxSize, lj.MaxBackups, lj.MaxAge)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader("log:\n   file: /var/log/tdns/x.log\n   max-backups: 7\n")); err != nil {
		t.Fatalf("viper read: %v", err)
	}
	var vconf Config
	if err := v.Unmarshal(&vconf); err != nil {
		t.Fatalf("viper.Unmarshal: %v", err)
	}
	if lj := vconf.Log.rotatingWriter("f"); lj.MaxSize != 20 || lj.MaxBackups != 7 || lj.MaxAge != 14 {
		t.Errorf("viper: rotation = %d MB, %d backups, %d days; want 20, 7, 14", lj.MaxSize, lj.MaxBackups, lj.MaxAge)
	}
}

// A rotation key of zero or less is refused, by the early parse the daemon
// starts with and by config check alike. Lumberjack would read a 0 as "no
// limit", which is not what was written.
func TestALogRotationKeyOfZeroOrLessIsRefused(t *testing.T) {
	for _, tc := range []struct{ line, key string }{
		{"max-size: 0", "log.max-size"},
		{"max-backups: 0", "log.max-backups"},
		{"max-age: -1", "log.max-age"},
	} {
		cfg := writeCfg(t, "log:\n   file: /var/log/tdns/x.log\n   "+tc.line+"\n")
		if _, err := parseLogConfFromFile(cfg); err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("parseLogConfFromFile with %q: err = %v, want a %s error", tc.line, err, tc.key)
		}
		if err := ValidateConfig(nil, cfg); err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("ValidateConfig with %q: err = %v, want a %s error", tc.line, err, tc.key)
		}
	}
}
