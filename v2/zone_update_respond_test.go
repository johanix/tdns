/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"errors"
	"testing"
	"time"
)

// TestUpdateRequestRespondNeverBlocks is the safety property that matters here.
// UpdateRequest.respond is called from the single ZoneUpdater goroutine, which
// serves every zone on the server. If it could ever block -- on a caller that
// timed out and walked away, or on a second send from a belt-and-braces exit
// path -- one abandoned UPDATE would stall updates for the whole server.
func TestUpdateRequestRespondNeverBlocks(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)

		// No waiter at all.
		(&UpdateRequest{}).respond(true, nil)

		// A waiter that has gone away: buffered channel, nobody reading, and
		// then more sends than the buffer can hold.
		ur := &UpdateRequest{Resp: make(chan ZoneUpdateResult, 1)}
		ur.respond(true, nil)
		ur.respond(false, errors.New("second send from another exit path"))
		ur.respond(false, errors.New("third"))

		// An unbuffered channel nobody is reading -- the worst case.
		(&UpdateRequest{Resp: make(chan ZoneUpdateResult)}).respond(true, nil)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("respond blocked; an abandoned UPDATE would stall the ZoneUpdater for every zone")
	}
}

// The first outcome reported wins, so a later belt-and-braces send from another
// exit path cannot overwrite the real result with a spurious one.
func TestUpdateRequestRespondFirstResultWins(t *testing.T) {
	ur := &UpdateRequest{Resp: make(chan ZoneUpdateResult, 1)}

	ur.respond(true, nil)
	ur.respond(false, errors.New("later exit path"))

	res := <-ur.Resp
	if !res.Applied || res.Err != nil {
		t.Errorf("got %+v, want the first result (applied, no error)", res)
	}
}

func TestUpdateRequestRespondDeliversFailure(t *testing.T) {
	ur := &UpdateRequest{Resp: make(chan ZoneUpdateResult, 1)}
	want := errors.New("could not persist")
	ur.respond(false, want)

	res := <-ur.Resp
	if res.Applied {
		t.Error("a failed update was reported as applied")
	}
	if !errors.Is(res.Err, want) {
		t.Errorf("Err = %v, want %v", res.Err, want)
	}
}
