/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package externaldb

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/delegationtest"
	"github.com/miekg/dns"
)

// The MariaDB half of the suite runs against a live database named by
// TDNS_EXTERNALDB_DSN, e.g.
//
//	TDNS_EXTERNALDB_DSN='tdns:secret@tcp(127.0.0.1:3306)/tdnstest' go test ./...
//
// Each test creates its tables under a prefix of its own and drops them
// afterwards. Without the variable those tests skip; what remains runs
// against no database at all.
func liveDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TDNS_EXTERNALDB_DSN")
	if dsn == "" {
		t.Skip("set TDNS_EXTERNALDB_DSN to run against a MariaDB")
	}
	return dsn
}

func boolPtr(b bool) *bool { return &b }

var prefixCounter int

func liveStore(t *testing.T) *Store {
	t.Helper()
	prefixCounter++
	prefix := fmt.Sprintf("t%d_%d_", time.Now().UnixNano()%1_000_000, prefixCounter)
	s, err := Open(tdns.ExternalDBConf{
		DSN:         tdns.SensitiveString(liveDSN(t)),
		TLS:         boolPtr(false),
		TablePrefix: prefix,
		AutoMigrate: true,
		Timeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, tbl := range []string{"delegation", "delegation_log", "delegation_ack"} {
			_, _ = s.db.ExecContext(ctx, "DROP TABLE IF EXISTS "+s.table(tbl))
		}
	})
	return s
}

// The equivalence suite: the same table of behaviours the sqlite store runs
// in v2. The two must agree on every operation.
func TestExternalDBStoreSuite(t *testing.T) {
	liveDSN(t)
	delegationtest.RunStoreSuite(t, func(t *testing.T) tdns.DelegationStore { return liveStore(t) })
}

// One update is one change: every action of it appears in the log under one
// change_id with consecutive revisions, and the state table's revision is
// the log revision that last touched the row.
func TestExternalDBChangeGrouping(t *testing.T) {
	s := liveStore(t)
	ctx := context.Background()

	ur := tdns.UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: "parent.example.", Validated: true}
	for _, txt := range []string{
		"alpha.parent.example. 3600 IN NS ns.alpha.parent.example.",
		"ns.alpha.parent.example. 3600 IN A 192.0.2.51",
	} {
		rr, err := dns.NewRR(txt)
		if err != nil {
			t.Fatal(err)
		}
		ur.Actions = append(ur.Actions, rr)
	}
	if err := s.ApplyChildUpdate("parent.example.", ur); err != nil {
		t.Fatalf("ApplyChildUpdate: %v", err)
	}

	log, err := s.Log(ctx, "parent.example.", 0)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(log) != 2 {
		t.Fatalf("want 2 log rows, got %d", len(log))
	}
	if string(log[0].ChangeID) != string(log[1].ChangeID) {
		t.Fatalf("the two actions of one update carry different change ids")
	}
	if log[1].Revision != log[0].Revision+1 {
		t.Fatalf("revisions %d and %d are not consecutive", log[0].Revision, log[1].Revision)
	}
	if log[0].Channel != "update" || log[0].Op != "add" {
		t.Errorf("log row = %+v; want channel update, op add", log[0])
	}

	// A second update for the same child makes a second change, and the
	// deletion is logged with the record it removed.
	del, _ := dns.NewRR("ns.alpha.parent.example. 0 IN A 192.0.2.51")
	del.Header().Class = dns.ClassNONE
	if err := s.ApplyChildUpdate("parent.example.", tdns.UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: "parent.example.", Actions: []dns.RR{del}}); err != nil {
		t.Fatal(err)
	}
	first := string(log[0].ChangeID)
	log, _ = s.Log(ctx, "parent.example.", log[1].Revision)
	if len(log) != 1 || log[0].Op != "del-rr" {
		t.Fatalf("after the delete: %+v", log)
	}
	if string(log[0].ChangeID) == first {
		t.Fatal("the delete reused the first update's change id")
	}
	if !strings.Contains(log[0].RR, "192.0.2.51") {
		t.Errorf("the delete's log row does not name the record: %+v", log[0])
	}

	// origin: asserted for the child's rows; adoption writes observed and
	// the child's later assertion supersedes it.
	origins, _ := s.Origins(ctx, "parent.example.", "alpha.parent.example.")
	for rr, o := range origins {
		if o != "asserted" {
			t.Errorf("%s has origin %s", rr, o)
		}
	}
	obs, _ := dns.NewRR("bravo.parent.example. 3600 IN NS ns.bravo.example.")
	if n, err := s.AdoptChildDelegation("parent.example.", "bravo.parent.example.", []dns.RR{obs}); err != nil || n != 1 {
		t.Fatalf("adopt: n=%d err=%v", n, err)
	}
	origins, _ = s.Origins(ctx, "parent.example.", "bravo.parent.example.")
	for _, o := range origins {
		if o != "observed" {
			t.Errorf("adopted row has origin %s", o)
		}
	}
	if err := s.ApplyChildUpdate("parent.example.", tdns.UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: "parent.example.", Actions: []dns.RR{obs}}); err != nil {
		t.Fatal(err)
	}
	origins, _ = s.Origins(ctx, "parent.example.", "bravo.parent.example.")
	for _, o := range origins {
		if o != "asserted" {
			t.Errorf("the child's assertion did not supersede the observation: %s", o)
		}
	}
}

// The startup check names what is missing, for a schema that was not made
// by tdns or has drifted, and Open refuses.
func TestExternalDBSchemaCheckNamesTheMissingColumn(t *testing.T) {
	s := liveStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, "ALTER TABLE "+s.table("delegation_log")+" DROP COLUMN principal"); err != nil {
		t.Fatalf("dropping a column for the test: %v", err)
	}
	err := s.VerifySchema(ctx)
	if err == nil || !strings.Contains(err.Error(), "lacks column(s) principal") {
		t.Fatalf("want the missing column named, got %v", err)
	}
	_, err = Open(tdns.ExternalDBConf{
		DSN: tdns.SensitiveString(liveDSN(t)), TLS: boolPtr(false), TablePrefix: s.prefix, Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("Open accepted a schema that fails the check")
	}
}

// A store that cannot be reached is a refusal, never a NOERROR for something
// unrecorded (D-2): Open fails, and so does every call on a store whose
// database went away.
func TestExternalDBOutageIsARefusal(t *testing.T) {
	_, err := Open(tdns.ExternalDBConf{
		DSN: "tdns:x@tcp(127.0.0.1:1)/nothing", TLS: boolPtr(false), Timeout: 300 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "cannot reach") {
		t.Fatalf("want a refusal to open, got %v", err)
	}
}

func TestDSNFoldsPasswordTLSAndTimeouts(t *testing.T) {
	dsn, err := mariadbDSN(tdns.ExternalDBConf{
		DSN: "tdns@tcp(db.example.net:3306)/reg", Password: "s3cret", Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tdns:s3cret@tcp(db.example.net:3306)/reg", "tls=tdns-external-db", "parseTime=true", "timeout=2s", "readTimeout=2s"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("dsn lacks %q: %s", want, dsn)
		}
	}
	// Loopback: no TLS unless asked for.
	dsn, _ = mariadbDSN(tdns.ExternalDBConf{DSN: "tdns:pw@tcp(127.0.0.1:3306)/reg"})
	if strings.Contains(dsn, "tls=") {
		t.Errorf("loopback got TLS by default: %s", dsn)
	}
	dsn, _ = mariadbDSN(tdns.ExternalDBConf{DSN: "tdns:pw@tcp(127.0.0.1:3306)/reg", TLS: boolPtr(true)})
	if !strings.Contains(dsn, "tls=tdns-external-db") {
		t.Errorf("tls: true was ignored on loopback: %s", dsn)
	}
	// A unix socket is local by definition: no TLS unless asked for, and
	// asking for it is refused in words, since there is no name to verify.
	dsn, _ = mariadbDSN(tdns.ExternalDBConf{DSN: "tdns:pw@unix(/var/run/mysqld.sock)/reg"})
	if strings.Contains(dsn, "tls=") {
		t.Errorf("a unix socket got TLS by default: %s", dsn)
	}
	if _, err := mariadbDSN(tdns.ExternalDBConf{DSN: "tdns:pw@unix(/var/run/mysqld.sock)/reg", TLS: boolPtr(true)}); err == nil || !strings.Contains(err.Error(), "names no server to verify") {
		t.Errorf("tls on a unix socket must be refused in words, got %v", err)
	}
	// Two configurations register two TLS names: the registry is global.
	a, _ := mariadbDSN(tdns.ExternalDBConf{DSN: "tdns:pw@tcp(db-a.example.net:3306)/reg"})
	b, _ := mariadbDSN(tdns.ExternalDBConf{DSN: "tdns:pw@tcp(db-b.example.net:3306)/reg"})
	tlsName := func(dsn string) string {
		i := strings.Index(dsn, "tls=")
		rest := dsn[i+4:]
		if j := strings.Index(rest, "&"); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	if tlsName(a) == tlsName(b) {
		t.Errorf("two hosts share one TLS registration: %s", tlsName(a))
	}
	if _, err := mariadbDSN(tdns.ExternalDBConf{DSN: "not a dsn at all"}); err == nil {
		t.Error("a malformed dsn was accepted")
	}
}

func TestDDLRendersThePrefix(t *testing.T) {
	ddl := DDL("reg_")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS reg_delegation (",
		"CREATE TABLE IF NOT EXISTS reg_delegation_log (",
		"CREATE TABLE IF NOT EXISTS reg_delegation_ack (",
		"CONSTRAINT reg_chk_origin",
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("DDL lacks %q", want)
		}
	}
	if strings.Contains(ddl, "%s") {
		t.Error("DDL has an unrendered placeholder")
	}
}

// Importing this package is what makes the store exist in a binary.
func TestRegisteredAsExternalDB(t *testing.T) {
	for _, n := range tdns.RegisteredDelegationStores() {
		if n == tdns.DelegationStoreExternalDB {
			return
		}
	}
	t.Fatal("external-db is not registered")
}

func TestUnsupportedDriverAndMissingDSN(t *testing.T) {
	if _, err := Open(tdns.ExternalDBConf{Driver: "oracle", DSN: "x"}); err == nil || !strings.Contains(err.Error(), "unsupported driver") {
		t.Errorf("unsupported driver: %v", err)
	}
	if _, err := Open(tdns.ExternalDBConf{}); err == nil || !strings.Contains(err.Error(), "dsn is required") {
		t.Errorf("missing dsn: %v", err)
	}
	// The prefix is formatted into every statement; only an identifier
	// fragment is accepted, and it is refused before any connection.
	if _, err := Open(tdns.ExternalDBConf{DSN: "x@tcp(127.0.0.1:1)/db", TablePrefix: "bad prefix;"}); err == nil || !strings.Contains(err.Error(), "table-prefix") {
		t.Errorf("a bad prefix was accepted: %v", err)
	}
}
