//go:build !unix

/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import "context"

// lockCliConfig is a no-op where there is no flock(2). See the unix version.
func lockCliConfig(_ context.Context, path string) (func(), error) {
	return func() {}, nil
}
