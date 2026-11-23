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

// defaultConfigDir is where the daemons' config files are by default. A config
// file there names its default socket by its file name alone.
const defaultConfigDir = "/etc/tdns"

// ApiSocketPath is the local admin socket of the daemon whose config file is
// cfgfile and whose apiserver.socket is configured: that path when it is set,
// no socket ("") for "none", and, when it is not set, the default in
// DefaultApiSocketDir, named after the config file:
//
//	/etc/tdns/tdns-auth.yaml       -> /var/run/tdns/tdns-auth.sock
//	/etc/tdns-site/tdns-auth.yaml  -> /var/run/tdns/etc-tdns-site-tdns-auth.sock
//
// A file in /etc/tdns by its name; any other by its whole path, because
// instances in other directories commonly share a file name (testor runs
// tdns-auth.yaml from /etc/tdns, /etc/tdns-site and /etc/tdns-enc), and two
// daemons must never share a socket: the second would serve none, and
// tdns-ncli would reach the first through the second's entry. A path too long
// for a socket is shortened to the file name and a hash of the path.
//
// Every daemon has the socket unless told otherwise. It is the way in when the
// network API is not (a broken TLS setup, a lost key), and a way in that has
// to be configured beforehand is missing exactly then. tdns-ncli works the
// socket out the same way from an entry's config-file:, so no CLI config
// repeats the path.
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
	noExt := strings.TrimSuffix(abs, filepath.Ext(abs))
	base := filepath.Base(noExt)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return ""
	}
	name := base
	if filepath.Dir(abs) != defaultConfigDir {
		name = strings.ReplaceAll(strings.TrimPrefix(noExt, string(filepath.Separator)), string(filepath.Separator), "-")
	}
	p := filepath.Join(DefaultApiSocketDir, name+".sock")
	if len(p) > maxApiSocketPathLen {
		sum := sha256.Sum256([]byte(abs))
		tail := "-" + hex.EncodeToString(sum[:4]) + ".sock"
		if room := maxApiSocketPathLen - len(DefaultApiSocketDir) - 1 - len(tail); len(base) > room {
			base = base[:max(room, 0)]
		}
		p = filepath.Join(DefaultApiSocketDir, base+tail)
	}
	return p
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
