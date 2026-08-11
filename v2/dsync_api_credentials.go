/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Credentials for the DSYNC API scheme (docs/2026-08-11-dsync-api-scheme.md
// §5, §10).
//
// The tuple is <username, key>, not a single shared API key, and the reason is
// authorization rather than authentication strength: a shared key names nobody,
// and a policy that cannot name the principal cannot be granular. The username
// identifies a principal; the principal is what updatepolicy.child is evaluated
// against, exactly where the SIG(0) signer name goes on the DDNS path.
//
// This is a separate credential space from apiserver.apikey. That key is a
// trusted-operator credential for the management API and grants the authority
// to do anything; these are registrant credentials, and every one of them is
// confined by the zone's update policy.

// DsyncApiKeyBytes is how much entropy a generated key carries. 256 bits, which
// is what lets the store hash with plain SHA-256 instead of a slow KDF.
const DsyncApiKeyBytes = 32

// DsyncApiCredential is one stored credential. The key itself is not a field:
// it exists in plaintext exactly once, in the return value of
// AddDsyncApiCredential, and is never recoverable afterwards.
type DsyncApiCredential struct {
	Id         int64
	ParentZone string
	Username   string
	Principal  string
	Created    time.Time
	Expires    time.Time // zero means never
	Disabled   bool
	Comment    string
}

// Expired reports whether the credential has passed its expiry.
func (c *DsyncApiCredential) Expired(now time.Time) bool {
	return !c.Expires.IsZero() && now.After(c.Expires)
}

// Usable reports whether the credential may authenticate a request right now.
func (c *DsyncApiCredential) Usable(now time.Time) bool {
	return !c.Disabled && !c.Expired(now)
}

// GenerateDsyncApiKey returns a fresh key in URL-safe base64.
//
// tdns generates these; it does not accept an operator-chosen key. A
// human-chosen password would be guessable enough to need a slow KDF on every
// request, and the whole storage design (§10) rests on not needing one.
func GenerateDsyncApiKey() (string, error) {
	buf := make([]byte, DsyncApiKeyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating DSYNC API key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashDsyncApiKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// canonDsyncApiZone normalises a parent zone name. It is a domain name, so it
// gets domain-name treatment: trailing dot supplied, case folded.
func canonDsyncApiZone(zone string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(zone)))
}

// canonDsyncApiUser normalises a username: trimmed, case-folded, and given a
// trailing dot.
//
// A username does not have to be a domain name -- the recommended convention is
// to name the account after the child zone, but "acme-registrar" is a perfectly
// good account name, and it is stored as "acme-registrar." here. What a
// username has to provide is uniqueness, and domain-name normalisation provides
// it while costing nothing.
//
// The alternative, folding case but leaving the dot alone, makes "bob" and
// "bob." two different accounts. Everywhere else in this system those two
// strings name the same thing, so a credential store where they do not is a
// trap: the account is provisioned one way, typed the other, and the failure is
// an indistinguishable 401 (§5) that says nothing about why.
//
// Case is folded for the same reason it is on any domain name, and because two
// accounts differing only in case is a way to end up with a credential nobody
// remembers issuing.
func canonDsyncApiUser(user string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(user)))
}

// usableAsPrincipal reports whether s can serve as a policy principal.
//
// dns.IsDomainName is not enough on its own: DNS labels may contain any octet,
// so it happily accepts "not a domain name" as a single label containing
// spaces. Such a principal is not an error the update policy would ever report
// -- it simply never matches any owner name, so every request 403s and the
// reason is nowhere. Cheaper to refuse it at provisioning.
func usableAsPrincipal(s string) bool {
	if s == "" || s == "." {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	_, ok := dns.IsDomainName(s)
	return ok
}

// AddDsyncApiCredential creates a credential and returns the plaintext key.
//
// The key is returned once and stored only as a hash. There is deliberately no
// way to read it back: a credential store that can show you the secret is one
// database read away from handing every registrant's secret to whoever can run
// a query.
//
// principal may be empty, in which case it is the username. It must be a
// domain name either way -- self/selfsub compare against one -- and that is
// checked here rather than at authentication time, where the failure would be
// a confusing 403 on every request instead of an error at provisioning.
func (kdb *KeyDB) AddDsyncApiCredential(parentZone, username, principal, comment string, expires time.Time) (string, error) {
	zone := canonDsyncApiZone(parentZone)
	user := canonDsyncApiUser(username)
	// Both normalise an empty string to ".", so that is what "missing" looks
	// like here. A username of "." alone is refused by the same check, which
	// is correct: it is the root, not a name.
	if zone == "." || user == "." {
		return "", fmt.Errorf("both a parent zone and a username are required")
	}

	princ := strings.TrimSpace(principal)
	if princ == "" {
		princ = user
	}
	if !usableAsPrincipal(princ) {
		return "", fmt.Errorf("principal %q is not a usable domain name; the update policy compares it against owner names", princ)
	}
	princ = strings.ToLower(dns.Fqdn(princ))

	key, err := GenerateDsyncApiKey()
	if err != nil {
		return "", err
	}

	var exp int64
	if !expires.IsZero() {
		exp = expires.Unix()
	}

	const q = `INSERT INTO DsyncApiCredential
	(parentzone, username, principal, keyhash, created, expires, disabled, comment)
	VALUES (?, ?, ?, ?, ?, ?, 0, ?)`

	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	if _, err := kdb.DB.Exec(q, zone, user, princ, hashDsyncApiKey(key),
		time.Now().Unix(), exp, comment); err != nil {
		return "", fmt.Errorf("storing DSYNC API credential for %s in %s: %v", user, zone, err)
	}
	return key, nil
}

// ListDsyncApiCredentials returns the credentials for a parent zone, or for
// every zone when parentZone is empty. Never returns key material.
func (kdb *KeyDB) ListDsyncApiCredentials(parentZone string) ([]DsyncApiCredential, error) {
	q := `SELECT id, parentzone, username, principal, created, expires, disabled, comment
	      FROM DsyncApiCredential`
	var args []interface{}
	if z := canonDsyncApiZone(parentZone); z != "." {
		q += ` WHERE parentzone = ?`
		args = append(args, z)
	}
	q += ` ORDER BY parentzone, username`

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	rows, err := kdb.DB.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing DSYNC API credentials: %v", err)
	}
	defer rows.Close()

	var out []DsyncApiCredential
	for rows.Next() {
		var c DsyncApiCredential
		var created, expires int64
		var disabled int
		var comment sql.NullString
		if err := rows.Scan(&c.Id, &c.ParentZone, &c.Username, &c.Principal,
			&created, &expires, &disabled, &comment); err != nil {
			return nil, fmt.Errorf("scanning DSYNC API credential: %v", err)
		}
		c.Created = time.Unix(created, 0)
		if expires != 0 {
			c.Expires = time.Unix(expires, 0)
		}
		c.Disabled = disabled != 0
		c.Comment = comment.String
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteDsyncApiCredential removes a credential outright. Returns whether a row
// was removed.
func (kdb *KeyDB) DeleteDsyncApiCredential(parentZone, username string) (bool, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	res, err := kdb.DB.Exec(`DELETE FROM DsyncApiCredential WHERE parentzone = ? AND username = ?`,
		canonDsyncApiZone(parentZone), canonDsyncApiUser(username))
	if err != nil {
		return false, fmt.Errorf("deleting DSYNC API credential: %v", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// SetDsyncApiCredentialDisabled turns a credential off or back on, keeping the
// row. Preferred over deletion when the question "who had access, and when"
// might be asked later.
func (kdb *KeyDB) SetDsyncApiCredentialDisabled(parentZone, username string, disabled bool) (bool, error) {
	d := 0
	if disabled {
		d = 1
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	res, err := kdb.DB.Exec(`UPDATE DsyncApiCredential SET disabled = ? WHERE parentzone = ? AND username = ?`,
		d, canonDsyncApiZone(parentZone), canonDsyncApiUser(username))
	if err != nil {
		return false, fmt.Errorf("updating DSYNC API credential: %v", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// dsyncApiDummyHash is compared against when no credential matches, so that an
// unknown username and a wrong key take the same path through the comparison
// rather than the unknown one returning early.
var dsyncApiDummyHash = hashDsyncApiKey("this key does not exist")

// VerifyDsyncApiCredential authenticates a <username, key> pair against a
// parent zone and returns the credential on success.
//
// Failure is deliberately undifferentiated: unknown user, wrong key, disabled
// and expired all return the same error, and the caller answers 401 with no
// body. Telling an unauthenticated client that a username exists is telling it
// which name to keep guessing at.
func (kdb *KeyDB) VerifyDsyncApiCredential(parentZone, username, key string) (*DsyncApiCredential, error) {
	zone := canonDsyncApiZone(parentZone)
	user := canonDsyncApiUser(username)

	const q = `SELECT id, parentzone, username, principal, keyhash, created, expires, disabled, comment
	           FROM DsyncApiCredential WHERE parentzone = ? AND username = ?`

	kdb.mu.Lock()
	row := kdb.DB.QueryRow(q, zone, user)

	var c DsyncApiCredential
	var storedHash string
	var created, expires int64
	var disabled int
	var comment sql.NullString
	err := row.Scan(&c.Id, &c.ParentZone, &c.Username, &c.Principal, &storedHash,
		&created, &expires, &disabled, &comment)
	kdb.mu.Unlock()

	if err != nil {
		if err != sql.ErrNoRows {
			return nil, fmt.Errorf("looking up DSYNC API credential: %v", err)
		}
		// Compare anyway, against a hash of nothing in particular, so that a
		// miss does not return measurably faster than a wrong key.
		subtle.ConstantTimeCompare([]byte(hashDsyncApiKey(key)), []byte(dsyncApiDummyHash))
		return nil, fmt.Errorf("authentication failed")
	}

	if subtle.ConstantTimeCompare([]byte(hashDsyncApiKey(key)), []byte(storedHash)) != 1 {
		return nil, fmt.Errorf("authentication failed")
	}

	c.Created = time.Unix(created, 0)
	if expires != 0 {
		c.Expires = time.Unix(expires, 0)
	}
	c.Disabled = disabled != 0
	c.Comment = comment.String

	// Checked after the key comparison, not before: a client that guesses a
	// wrong key for a disabled account must not learn that the account is
	// merely disabled rather than nonexistent.
	if !c.Usable(time.Now()) {
		lgApi.Warn("DSYNC API credential refused", "zone", zone, "user", user,
			"disabled", c.Disabled, "expired", c.Expired(time.Now()))
		return nil, fmt.Errorf("authentication failed")
	}

	return &c, nil
}
