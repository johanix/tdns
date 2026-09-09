/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package externaldb

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	tdns "github.com/johanix/tdns/v2"
)

// The dialect shim. Two constructs differ between MariaDB and PostgreSQL and
// nothing else in this package's SQL does: the placeholder style and the
// upsert. MariaDB is what ships; the shim exists so that adding a driver is a
// config value rather than a refactor (design §5.8.3).
type dialect struct {
	name       string // the config's driver: name
	driverName string // what database/sql opens
	// placeholder renders the i-th (1-based) parameter marker.
	placeholder func(i int) string
	// upsertState is the state-table upsert, with %s for the table name.
	// The parameter order is parent, child, owner, rrtype, rr, rr_hash,
	// origin, revision.
	upsertState string
	// dsn turns the config into a driver DSN.
	dsn func(c tdns.ExternalDBConf) (string, error)
	// ddl is the schema, one statement per table, with %s for the prefix.
	ddl []string
}

var dialects = map[string]*dialect{
	"mysql":   mariadbDialect,
	"mariadb": mariadbDialect,
}

var mariadbDialect = &dialect{
	name:        "mysql",
	driverName:  "mysql",
	placeholder: func(int) string { return "?" },
	// A child's assertion replaces the row's child, origin and revision; the
	// key (parent, owner, rrtype, rr_hash) is what identifies it. VALUES()
	// rather than the newer alias form, which MariaDB does not accept.
	upsertState: `INSERT INTO %s (parent, child, owner, rrtype, rr, rr_hash, origin, revision, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(3))
ON DUPLICATE KEY UPDATE child = VALUES(child), origin = VALUES(origin), revision = VALUES(revision), updated_at = NOW(3)`,
	dsn: mariadbDSN,
	ddl: mariadbDDL,
}

// mariadbDSN builds the driver DSN from the config: the operator's dsn with
// the password, the TLS setting and the timeouts folded in. The password
// may be in the DSN or in its own field; its own field wins.
func mariadbDSN(c tdns.ExternalDBConf) (string, error) {
	cfg, err := mysql.ParseDSN(c.DSN.Value())
	if err != nil {
		return "", fmt.Errorf("external-db: cannot parse dsn: %w", err)
	}
	if pw := c.Password.Value(); pw != "" {
		cfg.Passwd = pw
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = timeoutOf(c)
	}
	cfg.ReadTimeout, cfg.WriteTimeout = timeoutOf(c), timeoutOf(c)
	cfg.ParseTime = true
	// Strict SQL mode is what makes a NOT NULL or CHECK violation an error
	// rather than a silently truncated row.
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["sql_mode"] = "'STRICT_ALL_TABLES'"

	// TLS on by default off loopback. A unix socket is local by definition
	// (and cannot carry TLS at all). There is no switch for turning
	// verification off; ca-file is how a private CA is trusted.
	wantTLS := cfg.Net != "unix" && !isLoopback(cfg.Addr)
	if c.TLS != nil {
		wantTLS = *c.TLS
	}
	if wantTLS {
		// TLS verifies a server NAME. A unix socket has none, and neither
		// does an address the driver could not split; refusing here beats
		// the handshake error the library would give later.
		host, _, err := net.SplitHostPort(cfg.Addr)
		if cfg.Net == "unix" || err != nil || host == "" {
			return "", fmt.Errorf("external-db: tls is on but the dsn address %q names no server to verify", cfg.Addr)
		}
		tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
		var pem []byte
		if c.CAFile != "" {
			pem, err = os.ReadFile(c.CAFile)
			if err != nil {
				return "", fmt.Errorf("external-db: reading ca-file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return "", fmt.Errorf("external-db: ca-file %s holds no certificate", c.CAFile)
			}
			tc.RootCAs = pool
		}
		// One registration per distinct configuration. The name is the DSN's
		// key into a process-global registry, so a shared name would make
		// the last zone's CA and server name apply to every store.
		sum := sha256.Sum256([]byte(host + "\x00" + c.CAFile + "\x00" + string(pem)))
		name := "tdns-external-db-" + hex.EncodeToString(sum[:8])
		if err := mysql.RegisterTLSConfig(name, tc); err != nil {
			return "", fmt.Errorf("external-db: registering the TLS config: %w", err)
		}
		cfg.TLSConfig = name
	}
	return cfg.FormatDSN(), nil
}

func isLoopback(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// defaultTimeout bounds one database call. The DSYNC service is only as
// available as the store, and a call that hangs is a child left waiting for
// an answer the ZoneUpdater cannot give while it waits here.
const defaultTimeout = 5 * time.Second

func timeoutOf(c tdns.ExternalDBConf) time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}
