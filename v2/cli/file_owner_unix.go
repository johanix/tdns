//go:build unix

/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"os"
	"syscall"
)

// fileOwner is fi's owner and group; ok is false where the platform does not
// say.
func fileOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
