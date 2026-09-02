package tdns

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReloadDelegationSyncFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tdns.yaml")
	body := []byte(`
delegationsync:
  policies:
    default:
      bootstrap:
        mechanisms: [at-ns]
        retry:
          max-attempts: 2
          interval: 7s
`)
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}

	if err := SetDelegationSyncConfig(DelegationSyncConf{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetDelegationSyncConfig(DelegationSyncConf{}) })

	conf := &Config{}
	conf.Internal.CfgFile = path
	if err := conf.reloadDelegationSyncFromFile(); err != nil {
		t.Fatal(err)
	}
	p, ok := lookupDelegationPolicy("default")
	if !ok || len(p.Mechanisms) != 1 || p.Mechanisms[0] != "at-ns" {
		t.Fatalf("reloaded policy: %+v", p)
	}
	if p.RetryInterval != 7*time.Second || p.RetryMaxAttempts != 2 {
		t.Fatalf("retry not decoded: %d/%s", p.RetryMaxAttempts, p.RetryInterval)
	}

	bad := []byte(`
delegationsync:
  policies:
    default:
      bootstrap:
        mechanisms: [at-apx]
`)
	if err := os.WriteFile(path, bad, 0644); err != nil {
		t.Fatal(err)
	}
	if err := conf.reloadDelegationSyncFromFile(); err == nil {
		t.Fatal("unknown mechanism must fail the reload")
	}
	p, _ = lookupDelegationPolicy("default")
	if len(p.Mechanisms) != 1 || p.Mechanisms[0] != "at-ns" {
		t.Fatalf("failed reload must keep previous policy, got %+v", p)
	}
}
