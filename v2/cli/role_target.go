/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Which daemon instance a command targets.
 *
 * A command tree carries its target as an annotation on the tree's ROOT, and
 * every command below it inherits that by walking up. This exists so a Run
 * closure can ask "which instance am I acting on?" without the answer having
 * been threaded down to it through every constructor in between.
 *
 * That matters because threading is exactly what had been getting forgotten.
 * 24 call sites in this package hardcoded GetApiClient("auth"), several inside
 * constructors declared `func newXxx(_ string)` -- the role not merely unused
 * there but explicitly discarded. With one instance of each daemon that is
 * invisible. With two, it silently drives the WRONG nameserver: no error, no
 * crash, a rollover executed against the other server. All 24 now resolve off
 * the command tree instead. See docs/2026-09-07-cli-multi-instance-design.md.
 *
 * The equivalent "agent" and "scanner" sites (parentsync_cmds.go,
 * agent_zone_cmds.go, scanner_cmds.go) are untouched: those daemons have no
 * per-instance tree factory yet, so their role is still correct by
 * construction. They become the same conversion the day one is wanted.
 *
 * A closure gets its *cobra.Command for free, so GetApiClientForCmd cannot be
 * forgotten in the way a threaded parameter can. Prefer it in new code.
 */
package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

// roleAnnotation is the cobra Annotations key holding a subtree's target role.
const roleAnnotation = "tdns.role"

// TagRole marks cmd -- and thus everything below it -- as targeting role.
// Returns cmd so it can be used inline in an AddCommand argument list.
func TagRole(cmd *cobra.Command, role string) *cobra.Command {
	if cmd == nil {
		return nil
	}
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[roleAnnotation] = role
	return cmd
}

// RoleForCmd returns the role cmd's tree targets, or "" if the tree is
// untagged. The walk is upward from cmd, so a subtree may override its
// parent's tag -- which is what lets a single tree host a command that
// deliberately talks to a different daemon.
func RoleForCmd(cmd *cobra.Command) string {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Annotations == nil {
			continue
		}
		if role, ok := c.Annotations[roleAnnotation]; ok && role != "" {
			return role
		}
	}
	return ""
}

// GetApiClientForCmd resolves the ApiClient for whichever instance cmd's tree
// targets.
//
// An untagged tree is a wiring bug, not a user error: every tree root is
// tagged where it is built. Say so plainly rather than falling back to a
// default role, because the failure a default would produce is the silent
// wrong-target one this whole mechanism exists to prevent.
func GetApiClientForCmd(cmd *cobra.Command, dieOnError bool) (*tdns.ApiClient, error) {
	role := RoleForCmd(cmd)
	if role == "" {
		name := "<nil>"
		if cmd != nil {
			name = cmd.CommandPath()
		}
		err := fmt.Errorf("command %q is in an untagged command tree: no target instance (this is a wiring bug -- see TagRole)", name)
		if dieOnError {
			log.Fatalf("%v", err)
		}
		return nil, err
	}
	return GetApiClient(role, dieOnError)
}

// The canonical daemon trees and the target each one drives.
//
// Tagged HERE rather than in each binary's wiring: every binary importing this
// package then gets the same answer, and GetApiClientForCmd resolves inside
// these trees for all of them. One binary tagging them was enough to make the
// package's own tests pass while leaving tdns-cli's rollover commands in an
// untagged tree -- a failure that is not a compile error, not a test failure
// in the command's own test, and shows up only when a command in the tree asks
// for its target and finds none.
//
// Kept in one place rather than an init() per command file for the same
// reason: a tag that lives next to the tree it describes is a tag that gets
// dropped when that file is refactored. TestCanonicalAuthTreeStillTargetsAuth
// guards the result either way.
//
// Instance trees do NOT appear here -- they tag themselves in NewAuthTree,
// because their targets come from config and are not known until run time.
func init() {
	TagRole(AuthCmd, "auth")
	TagRole(AgentCmd, "agent")
	TagRole(ImrCmd, "imr")
	TagRole(ScannerCmd, "scanner")
}
