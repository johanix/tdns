/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The local admin socket: the management API on a unix socket, authenticated
 * by file permissions. Design: docs/2026-11-20-api-pinning-mtls-roles-design.md
 * section 3.2.
 */
package tdns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// localSocketKey marks a request that arrived on the local admin socket.
type localSocketKey struct{}

// FromLocalSocket reports whether the request whose context this is arrived
// on the local admin socket. Set by the socket's http.Server (ConnContext) and
// by nothing else, so a TCP client cannot claim it.
func FromLocalSocket(ctx context.Context) bool {
	v, _ := ctx.Value(localSocketKey{}).(bool)
	return v
}

// maxApiSocketPathLen keeps the path inside the smallest sun_path in use (104
// bytes on the BSDs and macOS, 108 on Linux), with room to spare.
const maxApiSocketPathLen = 100

// prepareApiSocket checks that path is a place the admin socket may be served
// from and clears a stale socket left by a crash.
//
// Whoever can open the socket is admin, so the directory it lives in is what
// keeps everyone else out: it must be a real directory (not a symlink) that
// group and others cannot enter. A missing directory is created with mode
// 0700. An existing socket file is removed only if it is a socket and nothing
// answers on it; a live one belongs to another process, and anything that is
// not a socket is left alone.
func prepareApiSocket(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("apiserver.socket %q is not an absolute path", path)
	}
	if len(path) > maxApiSocketPathLen {
		return fmt.Errorf("apiserver.socket %q is %d bytes; a unix socket path may be at most %d here",
			path, len(path), maxApiSocketPathLen)
	}

	dir := filepath.Dir(path)
	fi, err := os.Lstat(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
		// MkdirAll applies the umask; say exactly what is meant.
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory (a symlink is refused too)", dir)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s is accessible to group or others (mode %04o); whoever can open the admin socket is admin, so its directory must be 0700",
			dir, fi.Mode().Perm())
	}

	fi, err = os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return err
	case fi.Mode()&os.ModeSocket == 0:
		return fmt.Errorf("%s exists and is not a socket; not removing it", path)
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return fmt.Errorf("%s is in use by another process", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing the stale socket %s: %w", path, err)
	}
	return nil
}

// serveApiSocket serves router on the unix socket at path until done is
// closed. Requests on it carry FromLocalSocket, which the key check honours in
// place of a key. The socket file is mode 0600 and goes away at shutdown.
func serveApiSocket(path string, router http.Handler, done <-chan struct{}) error {
	if err := prepareApiSocket(path); err != nil {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	srv := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, localSocketKey{}, true)
		},
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			lgApi.Error("local admin socket stopped", "socket", path, "err", err)
		}
	}()
	go func() {
		<-done
		if err := srv.Shutdown(context.Background()); err != nil {
			lgApi.Error("local admin socket shutdown failed", "socket", path, "err", err)
		}
		os.Remove(path) // the listener normally unlinks it; this is belt and braces
	}()
	lgApi.Info("serving the management API on the local admin socket", "socket", path)
	return nil
}
