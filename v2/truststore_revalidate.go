/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// revalidateWait is how long "truststore sig0 revalidate" waits for the
// verification it starts, so that the common case -- the KEY is where the
// parent looks, and the first attempt accepts it -- is answered with the
// outcome. A verification that has to retry outlives it and is reported as
// running.
const revalidateWait = 5 * time.Second

// childKeyVerificationTrigger starts the verification of child's key keyid
// and returns a channel closed when it ends, or nil when none was started.
// KeyDB.TriggerChildKeyVerification in production.
type childKeyVerificationTrigger func(child string, keyid uint16, keyRR string) <-chan struct{}

// revalidateChildKey is "truststore sig0 revalidate" (#1172): the parent's
// operator has a child key that is not trusted verified again now.
//
// It runs the verification a re-bootstrap starts, without the re-bootstrap's
// cooldown (childKeyReBootstrapCooldown): that bounds what a child can make
// the parent do, and this is the parent's own operator. The one-at-a-time rule
// still holds, since a second verifier would race the first for the same row.
// Before, the only way to have a failed key looked at again before the
// cooldown ended was to delete its row and have the child upload it anew.
//
// The recorded failure is cleared first, so that while the verification runs
// the key reads as being verified, not as failed. It is recorded again if this
// verification fails too.
//
// It takes the API's open transaction and always ends it: the row has to be
// committed before the verifier, which writes it in a transaction of its own,
// starts.
func (kdb *KeyDB) revalidateChildKey(tx *Tx, child string, keyid uint16, trigger childKeyVerificationTrigger, wait time.Duration) (*TruststoreResponse, error) {
	resp := &TruststoreResponse{Time: time.Now()}
	fail := func(err error) (*TruststoreResponse, error) {
		tx.Rollback()
		resp.Error = true
		resp.ErrorMsg = err.Error()
		return resp, err
	}
	if child == "" {
		return fail(errors.New("revalidate needs the child's name"))
	}
	if childKeyVerificationRunning(child, keyid) {
		return fail(fmt.Errorf("a verification of SIG(0) key %d for %s is already running; it will decide", keyid, child))
	}

	var trusted bool
	var keyRR string
	err := tx.QueryRow(`SELECT trusted, keyrr FROM Sig0TrustStore WHERE zonename=? AND keyid=?`, child, keyid).Scan(&trusted, &keyRR)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(fmt.Errorf("no SIG(0) key %d for %s in the truststore", keyid, child))
	}
	if err != nil {
		return fail(fmt.Errorf("read SIG(0) key %d for %s: %w", keyid, child, err))
	}
	if trusted {
		return fail(fmt.Errorf("SIG(0) key %d for %s is already trusted; there is nothing to revalidate", keyid, child))
	}

	if _, err := tx.Exec(`UPDATE Sig0TrustStore SET validation_failed=0, validation_error='', validation_failed_at='' WHERE zonename=? AND keyid=? AND trusted=0`,
		child, keyid); err != nil {
		return fail(fmt.Errorf("clear the recorded failure of SIG(0) key %d for %s: %w", keyid, child, err))
	}
	kdb.dropSig0CacheEntry(tx, fmt.Sprintf("%s::%d", child, keyid))
	if err := tx.Commit(); err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("commit: %v", err)
		return resp, err
	}

	lgSigner.Info("operator revalidates a child SIG(0) key", "zone", child, "keyid", keyid)
	done := trigger(child, keyid, keyRR)
	if done == nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("verification of SIG(0) key %d for %s not started: one started meanwhile, or the delegation policy lists no verification mechanisms", keyid, child)
		return resp, nil
	}

	select {
	case <-done:
	case <-time.After(wait):
		resp.Msg = fmt.Sprintf("verification of SIG(0) key %d for %s started and still running (it retries); \"truststore sig0 list\" shows the outcome", keyid, child)
		return resp, nil
	}
	sk, err := kdb.FindSig0TrustedKey(child, keyid)
	switch {
	case err != nil:
		resp.Msg = fmt.Sprintf("verification of SIG(0) key %d for %s ended; reading the outcome failed: %v", keyid, child, err)
	case sk.Trusted:
		resp.Msg = fmt.Sprintf("SIG(0) key %d for %s verified and trusted", keyid, child)
	case sk.ValidationFailed:
		resp.Msg = fmt.Sprintf("SIG(0) key %d for %s still failed validation: %s", keyid, child, sk.ValidationError)
	default:
		resp.Msg = fmt.Sprintf("verification of SIG(0) key %d for %s ended without a verdict; see the log", keyid, child)
	}
	return resp, nil
}

// triggerFor binds TriggerChildKeyVerification to ctx, the context the
// verification runs under: the daemon's, not the API request's, which ends
// long before a verification that retries.
func (kdb *KeyDB) triggerFor(ctx context.Context) childKeyVerificationTrigger {
	return func(child string, keyid uint16, keyRR string) <-chan struct{} {
		return kdb.TriggerChildKeyVerification(ctx, child, "", keyid, keyRR)
	}
}
