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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

// DefaultApiSocketDir is the directory of a daemon's local admin socket when
// apiserver.socket is not set (ApiSocketPath). "" turns the default off,
// which the tests do, so that a daemon under test serves no socket in
// /var/run.
var DefaultApiSocketDir = "/var/run/tdns"

// ApiSocketNone is the apiserver.socket value that turns the socket off.
const ApiSocketNone = "none"

// ApiSocketPath is the local admin socket of the daemon whose config file is
// cfgfile and whose apiserver.socket is configured: that path when it is set,
// no socket ("") for "none", and, when it is not set, the default in
// DefaultApiSocketDir, named after the config file's whole path:
//
//	/etc/tdns/tdns-auth.yaml       -> /var/run/tdns/etc_tdns_tdns-auth.yaml.sock
//	/etc/tdns-site/tdns-auth.yaml  -> /var/run/tdns/etc_tdns-site_tdns-auth.yaml.sock
//
// The whole path, always, extension included: the socket's name says at once
// which config it belongs to (the owner's ruling), and two configs never
// share a socket, even when instances in different directories share a file
// name (testor runs tdns-auth.yaml from /etc/tdns, /etc/tdns-site and
// /etc/tdns-enc). A shared socket would leave the second daemon without its
// way in. "/" becomes "_", and a "_", "%" or any character but a letter,
// digit, "." or "-" in the path itself is %-escaped, so no two paths give one
// name (/etc/tdns-site/x.yaml and /etc/tdns/site/x.yaml stay apart). A path
// too long for a socket becomes the escaped file name, "%%" (which no escaped
// path contains) and a hash of the path.
func ApiSocketPath(configured, cfgfile string) string {
	switch {
	case strings.EqualFold(configured, ApiSocketNone):
		return ""
	case configured != "":
		return configured
	case cfgfile == "" || DefaultApiSocketDir == "":
		return ""
	}
	abs, err := filepath.Abs(cfgfile)
	if err != nil {
		return ""
	}
	rel := strings.TrimPrefix(filepath.ToSlash(abs), "/")
	if rel == "" {
		return ""
	}
	p := filepath.Join(DefaultApiSocketDir, socketNameEscape(rel)+".sock")
	if len(p) > maxApiSocketPathLen {
		sum := sha256.Sum256([]byte(abs))
		tail := "%%" + hex.EncodeToString(sum[:4]) + ".sock"
		base := socketNameEscape(filepath.Base(abs))
		if room := maxApiSocketPathLen - len(DefaultApiSocketDir) - 1 - len(tail); len(base) > room {
			base = base[:max(room, 0)]
		}
		p = filepath.Join(DefaultApiSocketDir, base+tail)
	}
	return p
}

// socketNameEscape is path (slash-separated, no leading slash) as one file
// name: "/" becomes "_"; letters, digits, "." and "-" stay; anything else,
// "_" and "%" included, becomes %XX. Different paths give different names.
func socketNameEscape(path string) string {
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c == '/':
			b.WriteByte('_')
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// CheckApiSocketPath says whether path can be an apiserver.socket at all: an
// absolute path short enough for a unix socket. A daemon serves no socket on a
// path this refuses, so a client must not expect one there either.
func CheckApiSocketPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("apiserver.socket %q is not an absolute path", path)
	}
	if len(path) > maxApiSocketPathLen {
		return fmt.Errorf("apiserver.socket %q is %d bytes; a unix socket path may be at most %d here",
			path, len(path), maxApiSocketPathLen)
	}
	return nil
}

// prepareApiSocket checks that path is a place the admin socket may be served
// from and clears a stale socket left by a crash.
//
// Whoever can open the socket is admin, so the directory it lives in is what
// keeps everyone else out: it must be a real directory (not a symlink) that
// group and others cannot enter. A missing directory is created with mode
// 0700. An existing socket file is removed only if it is a socket and nothing
// answers on it; a live one belongs to another process, and anything that is
// not a socket is left alone, as is a socket the probe gets anything but a
// refused connection from.
func prepareApiSocket(path string) error {
	if err := CheckApiSocketPath(path); err != nil {
		return err
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
	c, err := net.DialTimeout("unix", path, time.Second)
	switch {
	case err == nil:
		c.Close()
		return fmt.Errorf("%s is in use by another process", path)
	case errors.Is(err, os.ErrNotExist):
		return nil // gone since the Lstat
	case !errors.Is(err, syscall.ECONNREFUSED):
		// Only a refused connection says nobody listens there. Any other
		// failure (out of file descriptors, a busy listener) says nothing
		// about the socket, and removing a live daemon's socket would leave
		// that daemon running and unreachable.
		return fmt.Errorf("%s could not be probed (%v); not removing it", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing the stale socket %s: %w", path, err)
	}
	return nil
}

// apiSocketListener is the admin socket's listener. Closing it unlinks the
// socket file. It may be closed twice, by closeApiSockets on the way out and
// by the server's Shutdown, so only the first close does anything.
type apiSocketListener struct {
	net.Listener
	once sync.Once
	err  error
	// stopping is set by closeApiSockets before it closes the listener. A
	// close alone does not say the daemon is stopping: Serve also closes
	// the listener itself when Accept fails for good.
	stopping atomic.Bool
}

func (l *apiSocketListener) Close() error {
	l.once.Do(func() {
		l.err = l.Listener.Close()
	})
	return l.err
}

// serveFailure is the error to log when Serve on l returns err, or nil when
// Serve ended because the daemon is stopping.
func (l *apiSocketListener) serveFailure(err error) error {
	if err == nil || err == http.ErrServerClosed || l.stopping.Load() {
		return nil
	}
	return err
}

// apiSockets are the admin sockets this process serves.
var apiSockets struct {
	sync.Mutex
	lns []*apiSocketListener
}

// closeApiSockets closes every admin socket this process serves, which
// unlinks the socket files. The daemon calls it on its way out (MainLoop,
// Shutdowner). It cannot leave that to the servers' own shutdown: after an
// API stop the process exits before that shutdown gets to run, and after a
// signal it never starts. Connections in progress are left alone; the
// process is about to end them anyway.
func closeApiSockets() {
	apiSockets.Lock()
	lns := apiSockets.lns
	apiSockets.lns = nil
	apiSockets.Unlock()
	for _, l := range lns {
		l.stopping.Store(true)
		l.Close()
	}
}

// serveApiSocket serves router on the unix socket at path until done is
// closed. Requests on it carry FromLocalSocket, which the key check honours in
// place of a key. The socket file is mode 0600 and goes away when the daemon
// stops (closeApiSockets) or done is closed, whichever comes first. A failure
// to serve after it has started is passed to failed, if set; a stop is not.
func serveApiSocket(path string, router http.Handler, done <-chan struct{}, failed func(error)) error {
	if err := prepareApiSocket(path); err != nil {
		return err
	}
	raw, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		raw.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	ln := &apiSocketListener{Listener: raw}
	apiSockets.Lock()
	apiSockets.lns = append(apiSockets.lns, ln)
	apiSockets.Unlock()
	srv := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, localSocketKey{}, true)
		},
	}
	go serveOn(srv, ln, path, failed)
	go func() {
		<-done
		if err := srv.Shutdown(context.Background()); err != nil {
			lgApi.Error("local admin socket shutdown failed", "socket", path, "err", err)
		}
		// No os.Remove here: closing the listener (first thing Shutdown
		// does, unless closeApiSockets got there first) unlinks the
		// socket. Shutdown then waits for active requests, and a
		// replacement daemon may bind the path meanwhile; a remove after
		// the wait would delete its socket. A crash leaves a stale socket,
		// which prepareApiSocket clears at the next start.
	}()
	lgApi.Info("serving the management API on the local admin socket", "socket", path)
	return nil
}

// serveOn runs srv on ln until it ends. A failure, as opposed to a stop
// (serveFailure), is logged and passed to failed, if set.
func serveOn(srv *http.Server, ln *apiSocketListener, path string, failed func(error)) {
	if err := ln.serveFailure(srv.Serve(ln)); err != nil {
		lgApi.Error("local admin socket stopped", "socket", path, "err", err)
		if failed != nil {
			failed(err)
		}
	}
}

// apiSocketFailed records that the admin socket at sock stopped serving after
// it had started: a server error (Transport/ApiSocket), so `config status`
// shows the daemon as degraded and no longer as serving the socket.
func apiSocketFailed(conf *Config, sock string) func(error) {
	return func(err error) {
		conf.Internal.ServerErrors.set(ErrCatTransport, ErrSubApiSocket,
			fmt.Sprintf("local admin socket %s stopped serving: %v", sock, err))
	}
}
