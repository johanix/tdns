package tdns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// runTruststoreUpdate feeds one TRUSTSTORE-UPDATE to a live updater and waits
// for the reply channel. The engine is cancelled afterwards so the test does
// not leak a goroutine.
func runTruststoreUpdate(t *testing.T, kdb *KeyDB, ur UpdateRequest) ZoneUpdateResult {
	t.Helper()
	ur.Resp = make(chan ZoneUpdateResult, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = kdb.ZoneUpdaterEngine(ctx)
	}()

	kdb.UpdateQ <- ur
	kdb.UpdateQ <- UpdateRequest{Cmd: "PING"}

	var res ZoneUpdateResult
	select {
	case res = <-ur.Resp:
	case <-time.After(2 * time.Second):
		t.Fatal("updater did not answer the TRUSTSTORE-UPDATE")
	}
	cancel()
	<-done
	return res
}

func truststoreTestKEY(t *testing.T, owner string) *dns.KEY {
	t.Helper()
	k := testBulkSig0Key(t, owner)
	rr, err := dns.NewRR(k.KeyRR)
	if err != nil {
		t.Fatalf("parsing generated KEY: %v", err)
	}
	key, ok := rr.(*dns.KEY)
	if !ok {
		t.Fatalf("generated RR is %T, want *dns.KEY", rr)
	}
	return key
}

// A Begin failure used to fall through to tx.Commit() on a nil tx and panic.
// The RFC 2136 waiter would then sit out UpdateApplyTimeout. Fail closed.
func TestTruststoreUpdateBeginFailureAnswersAndDoesNotPanic(t *testing.T) {
	zd, kdb := updaterTestZone(t, Primary, map[ZoneOption]bool{})
	kdb.Ctx = "already-busy"

	res := runTruststoreUpdate(t, kdb, UpdateRequest{
		Cmd:      "TRUSTSTORE-UPDATE",
		ZoneName: zd.ZoneName,
		Actions:  []dns.RR{truststoreTestKEY(t, zd.ZoneName)},
	})
	if res.Applied {
		t.Error("a Begin failure was reported as applied")
	}
	if res.Err == nil {
		t.Fatal("expected an error, got none")
	}
	if !strings.Contains(res.Err.Error(), "not started") {
		t.Errorf("error = %v, want it to say the update was not started", res.Err)
	}
}

// Sig0TrustMgmt's SQL Exec path sets resp.Error and returns a nil error.
// Checking only err is how a KEY that was never stored was answered NOERROR.
func TestTruststoreUpdateStorageFailureIsNotReportedApplied(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	kdb := newTestKeyDB(t)
	zd.KeyDB = kdb
	if _, err := kdb.Exec("DROP TABLE Sig0TrustStore"); err != nil {
		t.Fatalf("DROP TABLE: %v", err)
	}

	res := runTruststoreUpdate(t, kdb, UpdateRequest{
		Cmd:      "TRUSTSTORE-UPDATE",
		ZoneName: zd.ZoneName,
		Actions:  []dns.RR{truststoreTestKEY(t, "child."+zd.ZoneName)},
	})
	if res.Applied {
		t.Error("a truststore write that failed was reported as applied")
	}
	if res.Err == nil {
		t.Fatal("expected an error, got none")
	}
}

func TestTruststoreUpdateRejectsNonKEY(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	kdb := newTestKeyDB(t)
	zd.KeyDB = kdb

	txt, err := dns.NewRR("child.example.test. 60 IN TXT \"not-a-key\"")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	res := runTruststoreUpdate(t, kdb, UpdateRequest{
		Cmd:      "TRUSTSTORE-UPDATE",
		ZoneName: zd.ZoneName,
		Actions:  []dns.RR{txt},
	})
	if res.Applied {
		t.Error("a non-KEY truststore update was reported as applied")
	}
	if res.Err == nil {
		t.Fatal("expected an error, got none")
	}
}

func TestTruststoreUpdateAddSucceeds(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	kdb := newTestKeyDB(t)
	zd.KeyDB = kdb
	key := truststoreTestKEY(t, "child."+zd.ZoneName)

	res := runTruststoreUpdate(t, kdb, UpdateRequest{
		Cmd:       "TRUSTSTORE-UPDATE",
		ZoneName:  zd.ZoneName,
		Actions:   []dns.RR{key},
		Validated: true,
		Trusted:   true,
	})
	if !res.Applied || res.Err != nil {
		t.Fatalf("successful add reported as failure: applied=%v err=%v", res.Applied, res.Err)
	}
	if _, ok := trustStoreEntry(t, kdb, key.Header().Name, key.KeyTag()); !ok {
		t.Fatal("KEY was not stored in the truststore")
	}
}
