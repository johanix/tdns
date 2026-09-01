/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"io"
	"log"
	"os"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
)

// ImrFlushCmd is ONE *cobra.Command registered into two binaries: tdns-imr
// (cmdv2/imr/shared_cmds.go) and tdns-cli (ImrCmd). Conf.Internal.RRsetCache
// means different things in each -- the live cache inside the daemon's shell,
// and nil in the separate CLI process.
//
// So the dispatch has to be right in both directions, and the dangerous one is
// sending the DAEMON down the API branch: that would be a TLS loopback call to
// itself, needing client config and an apikey a daemon has no reason to carry,
// to reach a cache it already holds a pointer to.
func TestFlushDispatch(t *testing.T) {
	savedType := tdns.Globals.App.Type
	savedCache := Conf.Internal.RRsetCache
	t.Cleanup(func() {
		tdns.Globals.App.Type = savedType
		Conf.Internal.RRsetCache = savedCache
	})

	// A stand-in for "this process owns a cache". Only its nil-ness is read.
	livecache := cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)

	for _, tc := range []struct {
		name    string
		app     tdns.AppType
		cache   bool // process holds a cache
		wantApi bool
	}{
		{"tdns-imr --cli, live cache", tdns.AppTypeImr, true, false},
		{"tdns-cli, no cache", tdns.AppTypeCli, false, true},

		// Belt and braces. Neither should happen; both must stay in-process,
		// because that is the behaviour that works today.
		{"tdns-cli somehow holding a cache", tdns.AppTypeCli, true, false},
		{"daemon with no cache yet", tdns.AppTypeImr, false, false},

		// An unset app type is what tdns-cli had before it identified itself.
		// It must NOT reach the API branch by accident.
		{"app type unset", 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tdns.Globals.App.Type = tc.app
			if tc.cache {
				Conf.Internal.RRsetCache = livecache
			} else {
				Conf.Internal.RRsetCache = nil
			}

			if got := flushViaApiWanted(); got != tc.wantApi {
				t.Errorf("flushViaApiWanted() = %v, want %v", got, tc.wantApi)
			}
		})
	}
}

// The role-scoped flushes (tdns-cli auth|agent imr flush) must be able to ask
// for the same thing the top-level tree can. They are always API-backed -- the
// auth and agent daemons are separate processes -- so they never touch the
// dispatch above, and it would be easy to extend one and forget the other.
func TestRoleScopedFlushCanKeepStructural(t *testing.T) {
	for _, role := range []string{"auth", "agent"} {
		t.Run(role, func(t *testing.T) {
			c := newImrFlushCmd(role)

			f := c.Flags().Lookup("keep-structural")
			if f == nil {
				t.Fatal("no --keep-structural flag: this role cannot ask for" +
					" what the top-level tree can")
			}
			if f.DefValue != "false" {
				t.Errorf("--keep-structural default = %q, want \"false\":"+
					" that is what this command has always sent", f.DefValue)
			}
		})
	}
}

// One sender for every API-backed flush. If a second one appears, the
// old-daemon warning will exist in one path and be forgotten in the other --
// which is the failure it exists to prevent.
func TestOnlyOneApiFlushSender(t *testing.T) {
	src, err := os.ReadFile("imr_cmds.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	agent, err := os.ReadFile("agent_imr_cmds.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := strings.Count(string(src), `Command: "imr-flush"`) +
		strings.Count(string(agent), `Command: "imr-flush"`); n != 1 {
		t.Errorf(`%d sites build an "imr-flush" request, want exactly 1`+
			" (SendImrFlush); a second one will not carry the old-daemon check", n)
	}
}
