/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import "time"

// A parent that reports our SIG(0) key's validation FAILED (KeyState 8, EDE
// KEY-VALIDATION-FAILED) looked a few times and did not accept the key. It
// keeps no state waiting for us (#677). What it could not find may still
// appear, typically a KEY our provider has not yet published at its signal
// name, and only the child knows when it asked for that. So the child
// re-bootstraps, which has the parent verify again, a few times with long waits
// between.

// childReBootstrapRounds is how many times a child re-bootstraps after its
// parent reports the key's validation failed, before it gives up and leaves
// the rest to the operator.
const childReBootstrapRounds = 4

// childReBootstrapFirstDelay is the wait before the first re-bootstrap. It
// must exceed the parent's cooldown (childKeyReBootstrapCooldown), or the
// re-bootstrap is refused and the round is wasted.
const childReBootstrapFirstDelay = 10 * time.Minute

// childReBootstrapDelay is the wait before re-bootstrap round (0-based): 10m,
// 20m, 40m, 80m, two and a half hours in all.
func childReBootstrapDelay(round int) time.Duration {
	d := childReBootstrapFirstDelay
	for i := 0; i < round; i++ {
		d *= 2
	}
	return d
}
