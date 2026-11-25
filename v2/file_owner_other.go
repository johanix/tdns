//go:build !unix

/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import "os"

// fileOwner: no owner to keep on this platform.
func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
