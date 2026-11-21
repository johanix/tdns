//go:build !unix

/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

// lockCliConfig is a no-op where there is no flock(2). See the unix version.
func lockCliConfig(path string) (func(), error) {
	return func() {}, nil
}
