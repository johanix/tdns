/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"fmt"
	"testing"
)

// The status code decides backoff and whether an operator is told to go and
// fix something, so the mapping is worth pinning: a 401 that came back as
// "transport" would retry a wrong credential forever, and a 503 that came back
// as "local-error" would send someone looking for a config bug that isn't
// there.
func TestClassifyDsyncApiPushFailure(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{400, SoftfailChildConfigLocalError}, // we sent something unacceptable
		{401, SoftfailChildConfigLocalError}, // our credential is wrong
		{403, SoftfailParentRejected},        // authenticated, policy said no
		{404, SoftfailParentRejected},        // no hosted parent / scheme not offered
		{409, SoftfailParentRejected},        // zone frozen at the parent
		{418, SoftfailParentRejected},        // any other 4xx: it answered and declined
		{500, SoftfailTransport},
		{503, SoftfailTransport}, // apply timed out; retry is the right move
	} {
		err := &DsyncApiHttpError{StatusCode: tc.status, Status: fmt.Sprintf("%d", tc.status)}
		if got := classifyDsyncApiPushFailure(err); got != tc.want {
			t.Errorf("status %d -> %q, want %q", tc.status, got, tc.want)
		}
		// Still classified correctly when wrapped, which is how it arrives.
		wrapped := fmt.Errorf("pushDSRRsetViaApi: %w", err)
		if got := classifyDsyncApiPushFailure(wrapped); got != tc.want {
			t.Errorf("wrapped status %d -> %q, want %q", tc.status, got, tc.want)
		}
	}
}

// Anything that never got an HTTP answer -- TLS refused, a redirect, a dead
// connection -- did not reach the parent, so it cannot be the parent's fault.
func TestClassifyDsyncApiPushFailureNonHttpIsTransport(t *testing.T) {
	for _, err := range []error{
		errors.New("dial tcp: connection refused"),
		errors.New("the endpoint redirected to https://elsewhere/; refusing to follow it"),
		fmt.Errorf("wrapped: %w", errors.New("x509: certificate signed by unknown authority")),
	} {
		if got := classifyDsyncApiPushFailure(err); got != SoftfailTransport {
			t.Errorf("%v -> %q, want %q", err, got, SoftfailTransport)
		}
	}
}

// DsyncApiHttpError must keep rendering the message it replaced, so anything
// reading logs sees no change.
func TestDsyncApiHttpErrorMessageUnchanged(t *testing.T) {
	e := &DsyncApiHttpError{StatusCode: 403, Status: "403 Forbidden", Body: "owner outside self"}
	want := "the parent refused the delegation update: 403 Forbidden: owner outside self"
	if e.Error() != want {
		t.Errorf("Error() = %q, want %q", e.Error(), want)
	}
	var target *DsyncApiHttpError
	if !errors.As(fmt.Errorf("ctx: %w", e), &target) || target.StatusCode != 403 {
		t.Error("errors.As did not recover the typed error through a wrap")
	}
}
