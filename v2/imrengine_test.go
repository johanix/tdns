/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"errors"
	"testing"
)

// TestBuildImrResponse_NilResponseAndError is the regression test for the
// crash that killed ns1.p.axfr.net (and would have killed any tdns binary
// embedding the IMR engine). The IMR's per-request goroutine previously
// inlined this normalisation as:
//
//	if err != nil {
//	    log
//	} else if resp == nil {
//	    resp = &ImrResponse{...}
//	}
//	sendResp(*resp)
//
// When err != nil AND resp == nil (the common case — ImrQuery returns
// (nil, ctxErr) when its context is canceled mid-walk), the else-if is
// skipped and *resp dereferences nil → panic → process crash (no recover()
// upstream). buildImrResponse handles both branches independently so the
// caller always has a non-nil response to send.
func TestBuildImrResponse_NilResponseAndError(t *testing.T) {
	err := errors.New("context canceled")
	got := buildImrResponse(nil, err)
	if !got.Error {
		t.Error("expected Error=true on err path")
	}
	if got.ErrorMsg != err.Error() {
		t.Errorf("ErrorMsg = %q, want %q", got.ErrorMsg, err.Error())
	}
}

// TestBuildImrResponse_NilResponseAndNoError handles the rare
// "ImrQuery returned (nil, nil)" path that the old code did handle.
func TestBuildImrResponse_NilResponseAndNoError(t *testing.T) {
	got := buildImrResponse(nil, nil)
	if !got.Error {
		t.Error("expected Error=true on nil-response path")
	}
	if got.ErrorMsg == "" {
		t.Error("expected non-empty ErrorMsg on nil-response path")
	}
}

// TestBuildImrResponse_NonNilResponseIsPassedThrough confirms the happy
// path: a real response is dereferenced and returned as-is.
func TestBuildImrResponse_NonNilResponseIsPassedThrough(t *testing.T) {
	in := &ImrResponse{Msg: "hello"}
	got := buildImrResponse(in, nil)
	if got.Error {
		t.Error("expected Error=false on happy path")
	}
	if got.Msg != "hello" {
		t.Errorf("Msg = %q, want %q", got.Msg, "hello")
	}
}

// TestBuildImrResponse_ErrTakesPrecedenceOverResponse: if both a response
// and an error are returned, the error path wins. (Defensive — ImrQuery
// shouldn't return both, but we shouldn't trust callers either.)
func TestBuildImrResponse_ErrTakesPrecedenceOverResponse(t *testing.T) {
	in := &ImrResponse{Msg: "stale"}
	got := buildImrResponse(in, errors.New("boom"))
	if !got.Error {
		t.Error("expected Error=true when both response and error are set")
	}
	if got.ErrorMsg != "boom" {
		t.Errorf("ErrorMsg = %q, want %q", got.ErrorMsg, "boom")
	}
}
