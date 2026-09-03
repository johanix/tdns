/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Auth methods recorded on DsyncApiCredential. "basic" is HTTP Basic; the
// tls-* names match the transfer-auth ladder.
const (
	DsyncApiAuthBasic   = "basic"
	DsyncApiAuthTLSPin  = MechTLSPin
	DsyncApiAuthTLSPkix = MechTLSPkix
)

// DsyncApiCertCredential is one stored certificate credential. The certificate
// itself is not stored: the identity is a pin or a DNS name, and the row maps
// that identity to a principal.
type DsyncApiCertCredential struct {
	Id         int64
	ParentZone string
	AuthMech   string
	Identity   string
	Principal  string
	Created    time.Time
	Expires    time.Time // zero means never
	Disabled   bool
	Comment    string
}

// Expired reports whether the credential has passed its expiry.
func (c *DsyncApiCertCredential) Expired(now time.Time) bool {
	return !c.Expires.IsZero() && now.After(c.Expires)
}

// Usable reports whether the credential may authenticate a request right now.
func (c *DsyncApiCertCredential) Usable(now time.Time) bool {
	return !c.Disabled && !c.Expired(now)
}

func (c DsyncApiCertCredential) asDsyncApiCredential() DsyncApiCredential {
	return DsyncApiCredential{
		Id:         c.Id,
		ParentZone: c.ParentZone,
		Username:   c.Identity,
		Principal:  c.Principal,
		Created:    c.Created,
		Expires:    c.Expires,
		Disabled:   c.Disabled,
		Comment:    c.Comment,
		AuthMethod: c.AuthMech,
	}
}

func validDsyncApiCertMech(mech string) bool {
	switch mech {
	case DsyncApiAuthTLSPin, DsyncApiAuthTLSPkix:
		return true
	}
	return false
}

// validDsyncApiSPKIPin reports whether s is the house pin format: 44 characters
// of canonical standard-encoding base64 of a SHA-256 digest. Hex, URL-safe,
// unpadded, and non-canonical padding-bit spellings are refused — pinMatches
// compares the base64 string, not the bytes.
func validDsyncApiSPKIPin(s string) bool {
	if len(s) != 44 {
		return false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

func canonDsyncApiCertIdentity(mech, identity string) (string, error) {
	identity = strings.TrimSpace(identity)
	switch mech {
	case DsyncApiAuthTLSPin:
		if !validDsyncApiSPKIPin(identity) {
			return "", fmt.Errorf("tls-pin identity is not a 44-character standard-encoding base64 SPKI SHA-256 (hex is refused; use --cert so the parent hashes the leaf)")
		}
		return identity, nil
	case DsyncApiAuthTLSPkix:
		name := core.CanonicalizeName(dns.Fqdn(identity))
		if name == "." || !usableAsPrincipal(name) {
			return "", fmt.Errorf("tls-pkix identity %q is not a usable DNS name", identity)
		}
		return name, nil
	default:
		return "", fmt.Errorf("unknown DSYNC API certificate mechanism %q (supported: tls-pin, tls-pkix)", mech)
	}
}

func scanDsyncApiCertCredential(scanner interface {
	Scan(dest ...interface{}) error
}) (DsyncApiCertCredential, error) {
	var c DsyncApiCertCredential
	var created, expires int64
	var disabled int
	var comment sql.NullString
	if err := scanner.Scan(&c.Id, &c.ParentZone, &c.AuthMech, &c.Identity,
		&c.Principal, &created, &expires, &disabled, &comment); err != nil {
		return DsyncApiCertCredential{}, err
	}
	c.Created = time.Unix(created, 0)
	if expires != 0 {
		c.Expires = time.Unix(expires, 0)
	}
	c.Disabled = disabled != 0
	c.Comment = comment.String
	return c, nil
}

// AddDsyncApiCertCredential stores a certificate credential. identity is a
// house-format pin for tls-pin, or a DNS name for tls-pkix.
func (kdb *KeyDB) AddDsyncApiCertCredential(parentZone, mech, identity, principal, comment string, expires time.Time) error {
	zone := canonDsyncApiZone(parentZone)
	if zone == "." {
		return fmt.Errorf("a parent zone is required")
	}
	mech = strings.ToLower(strings.TrimSpace(mech))
	if !validDsyncApiCertMech(mech) {
		return fmt.Errorf("unknown DSYNC API certificate mechanism %q (supported: tls-pin, tls-pkix)", mech)
	}
	ident, err := canonDsyncApiCertIdentity(mech, identity)
	if err != nil {
		return err
	}

	princ := strings.TrimSpace(principal)
	if princ == "" {
		if mech == DsyncApiAuthTLSPkix {
			princ = ident
		} else {
			return fmt.Errorf("a principal is required for a tls-pin credential; the pin is not a DNS name")
		}
	}
	if !usableAsPrincipal(princ) {
		return fmt.Errorf("principal %q is not a usable domain name; the update policy compares it against owner names", princ)
	}
	princ = core.CanonicalizeName(dns.Fqdn(princ))

	var exp int64
	if !expires.IsZero() {
		exp = expires.Unix()
	}

	const q = `INSERT INTO DsyncApiCertCredential
	(parentzone, authmech, identity, principal, created, expires, disabled, comment)
	VALUES (?, ?, ?, ?, ?, ?, 0, ?)`

	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	if _, err := kdb.DB.Exec(q, zone, mech, ident, princ, time.Now().Unix(), exp, comment); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("a %s credential for %q already exists in zone %s"+
				" (identities are normalised, so it may have been created with different"+
				" capitalisation or without the trailing dot)", mech, ident, zone)
		}
		return fmt.Errorf("storing DSYNC API %s credential for %s in %s: %v", mech, ident, zone, err)
	}
	return nil
}

// ListDsyncApiCertCredentials returns the certificate credentials for a parent
// zone, or for every zone when parentZone is empty.
func (kdb *KeyDB) ListDsyncApiCertCredentials(parentZone string) ([]DsyncApiCertCredential, error) {
	q := `SELECT id, parentzone, authmech, identity, principal, created, expires, disabled, comment
	      FROM DsyncApiCertCredential`
	var args []interface{}
	if z := canonDsyncApiZone(parentZone); z != "." {
		q += ` WHERE parentzone = ?`
		args = append(args, z)
	}
	q += ` ORDER BY parentzone, authmech, identity`

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	rows, err := kdb.DB.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing DSYNC API certificate credentials: %v", err)
	}
	defer rows.Close()

	var out []DsyncApiCertCredential
	for rows.Next() {
		c, err := scanDsyncApiCertCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning DSYNC API certificate credential: %v", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListDsyncApiAllCredentials returns bearer and certificate credentials in one
// slice, with AuthMethod set so an operator listing "who can update this zone"
// gets one answer.
func (kdb *KeyDB) ListDsyncApiAllCredentials(parentZone string) ([]DsyncApiCredential, error) {
	basic, err := kdb.ListDsyncApiCredentials(parentZone)
	if err != nil {
		return nil, err
	}
	certs, err := kdb.ListDsyncApiCertCredentials(parentZone)
	if err != nil {
		return nil, err
	}
	out := make([]DsyncApiCredential, 0, len(basic)+len(certs))
	out = append(out, basic...)
	for _, c := range certs {
		out = append(out, c.asDsyncApiCredential())
	}
	return out, nil
}

// LookupDsyncApiCertCredential returns the row for (zone, mech, identity), or
// nil if none exists. Does not consult Usable: the auth path does that after
// the proof succeeds.
func (kdb *KeyDB) LookupDsyncApiCertCredential(parentZone, mech, identity string) (*DsyncApiCertCredential, error) {
	zone := canonDsyncApiZone(parentZone)
	mech = strings.ToLower(strings.TrimSpace(mech))
	ident := strings.TrimSpace(identity)
	if mech == DsyncApiAuthTLSPkix {
		ident = core.CanonicalizeName(dns.Fqdn(ident))
	}

	const q = `SELECT id, parentzone, authmech, identity, principal, created, expires, disabled, comment
	           FROM DsyncApiCertCredential WHERE parentzone = ? AND authmech = ? AND identity = ?`

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	c, err := scanDsyncApiCertCredential(kdb.DB.QueryRow(q, zone, mech, ident))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("looking up DSYNC API certificate credential: %v", err)
	}
	return &c, nil
}

// DeleteDsyncApiCertCredential removes a certificate credential. Returns
// whether a row was removed.
func (kdb *KeyDB) DeleteDsyncApiCertCredential(parentZone, mech, identity string) (bool, error) {
	zone := canonDsyncApiZone(parentZone)
	mech = strings.ToLower(strings.TrimSpace(mech))
	ident, err := canonDsyncApiCertIdentity(mech, identity)
	if err != nil {
		return false, err
	}

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	res, err := kdb.DB.Exec(`DELETE FROM DsyncApiCertCredential WHERE parentzone = ? AND authmech = ? AND identity = ?`,
		zone, mech, ident)
	if err != nil {
		return false, fmt.Errorf("deleting DSYNC API certificate credential: %v", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// SetDsyncApiCertCredentialDisabled turns a certificate credential off or back
// on, keeping the row.
func (kdb *KeyDB) SetDsyncApiCertCredentialDisabled(parentZone, mech, identity string, disabled bool) (bool, error) {
	zone := canonDsyncApiZone(parentZone)
	mech = strings.ToLower(strings.TrimSpace(mech))
	ident, err := canonDsyncApiCertIdentity(mech, identity)
	if err != nil {
		return false, err
	}
	d := 0
	if disabled {
		d = 1
	}

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	res, err := kdb.DB.Exec(`UPDATE DsyncApiCertCredential SET disabled = ? WHERE parentzone = ? AND authmech = ? AND identity = ?`,
		d, zone, mech, ident)
	if err != nil {
		return false, fmt.Errorf("updating DSYNC API certificate credential: %v", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
