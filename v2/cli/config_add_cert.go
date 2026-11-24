/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * `tdns-ncli config add` and the operator's client certificate: making the
 * daemon accept it (its access file, and the access-file: line that names
 * that file), so the entry config add writes authenticates by certificate.
 * Design: docs/2026-11-20-api-pinning-mtls-roles-design.md, the amendment of
 * 2026-11-23 on config add.
 */
package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	tdns "github.com/johanix/tdns/v2"
)

// certState is where the operator's certificate stands with one daemon.
type certState int

const (
	certWorks     certState = iota // the access file in force lists the pin, enabled
	certCanEnable                  // config add can make it so from here
	certCannot                     // it cannot (CertSetup.why says why)
	certDisabled                   // the access file lists the pin, disabled
)

// CertSetup is what config add found about the operator's client certificate
// on one daemon, and what it did (or, in a dry run, would do) about it.
type CertSetup struct {
	info *DaemonApi // the daemon config, as config add read it
	role string     // the daemon type: auth, agent, imr
	word string     // the command word the advice uses: auth, auth2, ...

	cert, key string // the operator's pair
	pin       string // its pin; "" in a dry run before the pair exists
	pairNew   bool   // created by this add (dry run: would be)
	name      string // the name the access file gets for it

	t          *accessTarget
	listedAs   string // the access file already lists the pin, as this name
	listedRole string // and with this role
	byDaemon   bool   // the daemon said so (the access file could not be read)
	noTLS      bool   // the daemon's TCP API has no TLS
	noSocket   bool   // the daemon serves no local admin socket

	// Whether the daemon takes the API key on TCP: keyOff (keyWhy says
	// why not), or keyUnknown (why it cannot be told). Neither: it does.
	keyOff     bool
	keyWhy     string
	keyUnknown string

	// What making it work takes.
	addPin, createFile, nameIt bool
	daemonOld, daemonNew       []byte // the daemon config, and with access-file: added
	running                    bool   // the daemon on the socket runs this config
	dryRun                     bool

	state certState
	why   string // why it cannot work (certCannot)
	// pairProblem: it cannot work because the operator's own pair cannot be
	// used (0: not that), which the fix is about (there is no pin to enrol).
	pairProblem clientPairProblem
	// unidentified: it cannot work because the daemon on the local admin
	// socket could not be told to be this one (sockOther), which the fix is
	// about (enrolling does not help then); other is what it answered, nil
	// when it did not answer.
	unidentified bool
	other        *otherConfigError
	// timedOut: it cannot work, or apply failed, because the daemon did not
	// answer config add in time (a wedged daemon), which the fix is about;
	// nil when not that.
	timedOut *daemonTimeoutError
	// fileInvalid: it cannot work because the access file is not one the
	// daemon would load (ValidateAccessFile), whatever it lists.
	fileInvalid bool
	// sockMissing: the local admin socket's path does not exist (askDaemon).
	// sockGone: it cannot work because the daemon runs without it (removed
	// while it ran?), so nothing can reload it until it is restarted, which
	// the fix is about.
	sockMissing, sockGone bool
	// changed: it cannot work as planned because what planCert found had
	// changed when confirm looked again; config add, run again, plans anew.
	changed bool

	// What apply did.
	enrolledAs string     // the name the pin was added under
	reloaded   string     // the daemon's reply to the reload
	failed     error      // apply failed, and put everything back
	undo       []fileUndo // how to put back the files apply wrote
	didReload  bool       // apply reloaded the daemon
	reloadSent bool       // apply sent the daemon a reload (kept after a rollback)

	// held releases the locks (lockPaths) that a successful apply, or
	// confirm, keeps until the caller has written the CLI config (release)
	// or put the daemon's side back (rollback); nil when none are held.
	held func()
}

// fileUndo puts back one file apply wrote: old, or no file when old is nil;
// only while the file still holds wrote, so a later edit is not lost.
type fileUndo struct {
	path       string
	wrote, old []byte
}

// usable says whether the certificate works, or config add can make it work.
func (c *CertSetup) usable() bool {
	return c.state == certWorks || c.state == certCanEnable
}

// changesDaemon says whether making the certificate work takes config add
// doing something on the daemon's side (writing its files, reloading it).
func (c *CertSetup) changesDaemon() bool {
	return c.state == certCanEnable
}

func (c *CertSetup) cannot(why string) *CertSetup {
	c.state, c.why = certCannot, why
	return c
}

// pairCannot is cannot for the operator's own pair, which err says cannot be
// used: problem is what is wrong with it, unless err is a clientPairError,
// which says.
func (c *CertSetup) pairCannot(problem clientPairProblem, err error) *CertSetup {
	var pe *clientPairError
	if errors.As(err, &pe) {
		problem = pe.problem
	}
	c.pairProblem = problem
	return c.cannot(fmt.Sprintf("your client certificate cannot be used (%v)", err))
}

// planCert finds out where the operator's certificate stands with the daemon
// whose API info describes, and whether config add can make the daemon accept
// it. It changes nothing on the daemon's side; the operator's pair is created
// here when there is none (not in a dry run), as `client init` does. It also
// finds whether the daemon takes the API key (keyOff, keyUnknown), whatever
// becomes of the certificate: a known entry keeps the key only if it does.
//
// What the daemon takes is asked of the daemon, in this order (the owner's
// ruling): on its local socket, when that can be used (root), the policy in
// force; otherwise over its TCP API, pinned, with the client certificate and
// with the key (a ping says whether each is taken, and with which role); and
// only when the daemon is not running, its access file, which its next start
// reads. Nothing on its socket does not say it is not running (askDaemon):
// nothing on TCP either does.
//
// word is the command word the advice it prints uses for the daemon.
func planCert(o AddOptions, info *DaemonApi, word string) *CertSetup {
	c := &CertSetup{info: info, role: info.Role, word: word, t: accessTargetOf(info), dryRun: o.DryRun}

	relative := c.t.Configured && !filepath.IsAbs(c.t.File)
	af, old, aerr := c.readFile(relative)
	view, status, serr := c.askDaemon()
	if view == sockOther {
		// A socket that answers for another daemon, or with an error, is a
		// daemon that is not identified: neither it nor the file is taken.
		why := sockOtherWhy(serr)
		c.keyUnknown, c.unidentified = why, true
		errors.As(serr, &c.other)
		errors.As(serr, &c.timedOut)
		return c.cannot(why)
	}

	// The key.
	if view = c.findKey(view, status, serr); view == sockAbsent {
		c.keyFromFile(relative, old, af, aerr)
	}

	// Nothing to set up when a certificate cannot work on this daemon at
	// all: no pair is made for it.
	if !info.UseTLS {
		c.noTLS = true
		return c.cannot("the daemon's TCP API has no TLS (apiserver.usetls: false), which a client certificate needs")
	}
	if info.Socket == "" {
		c.noSocket = true
		why := "apiserver.socket: none"
		if info.SocketError != "" {
			why = info.SocketError
		}
		return c.cannot(fmt.Sprintf("the daemon serves no local admin socket (%s), which an access file needs", why))
	}

	// The operator's pair: the CLI config's client: block, else the default.
	// A dry run predicts it made only when neither file is there, as
	// ensureClientCert would make it (it never overwrites a key), and reads
	// a pair that is there without ensureClientCert, which makes a pair if
	// the certificate went meanwhile.
	c.cert, c.key = clientCertPaths(ReadCliClientConf(o.CliConfig))
	c.name = defaultClientName()
	_, cerr := os.Stat(c.cert)
	switch {
	case o.DryRun && cerr != nil && !errors.Is(cerr, fs.ErrNotExist):
		return c.pairCannot(pairBadCert, cerr)
	case o.DryRun && cerr != nil:
		_, kerr := os.Stat(c.key)
		switch {
		case kerr == nil:
			return c.pairCannot(pairKeyOnly, clientKeyWithoutCertError(c.cert, c.key))
		case !errors.Is(kerr, fs.ErrNotExist):
			return c.pairCannot(pairOther, kerr)
		}
		c.pairNew = true
	case o.DryRun:
		data, err := os.ReadFile(c.cert)
		pin := ""
		if err == nil {
			pin, err = clientPairPin(c.cert, c.key, data)
		}
		if err != nil {
			return c.pairCannot(pairBadCert, err) // unreadable, unless clientPairPin says
		}
		c.pin, c.name = pin, clientNameOf(c.cert)
	default:
		pin, created, err := ensureClientCert(c.cert, c.key, defaultClientName())
		if err != nil {
			return c.pairCannot(pairOther, err) // making it failed, unless it says
		}
		c.pin, c.pairNew, c.name = pin, created, clientNameOf(c.cert)
	}

	// The certificate, as the daemon takes it.
	switch view {
	case sockRunning:
		if a := status.Access; c.pin != "" && a != nil && a.Error == "" {
			for _, cl := range a.Clients {
				if cl.Pin == c.pin && !cl.Disabled {
					c.listedAs, c.listedRole, c.running, c.state = cl.Name, cl.Role, true, certWorks
					return c
				}
			}
		}
		// Not in force: config add makes it so, from the file (root reads
		// it), below.
	case sockShut:
		if c.timedOut != nil {
			// The key's ping got no answer: no second wait for this one.
			return c.cannot(c.timedOut.Error())
		}
		r := pingReply{}
		if c.pin != "" {
			if pair, err := tls.LoadX509KeyPair(c.cert, c.key); err == nil {
				r = c.ping(info, tdns.ClientOptions{AuthMethod: "certificate", ClientCert: &pair})
			}
		}
		switch {
		case r.taken && strings.EqualFold(r.pr.Via, "certificate"):
			c.listedAs, c.listedRole, c.byDaemon, c.state = r.pr.Identity, r.pr.Role, true, certWorks
			return c
		case r.answered && c.sockMissing:
			// It runs without the socket it makes when it starts (removed
			// since?): nothing can reload it until it is restarted, which
			// reads the access file again.
			c.sockGone = true
			return c.cannot(fmt.Sprintf("the daemon runs (it answers over TCP, and does not take your certificate), but its local admin socket %s does not exist, so nothing can reload it", c.t.Socket))
		case r.answered:
			// It runs, and does not take it. Nothing can be changed from
			// here (its socket is not ours to use, or it does not answer
			// there): what the file says only shapes the advice.
			if aerr == nil && !relative {
				if cl := clientByPin(af, c.pin); c.pin != "" && cl != nil {
					c.listedAs, c.listedRole = cl.Name, cl.Role
					if cl.Disabled {
						c.state = certDisabled
						return c
					}
					return c.cannot(fmt.Sprintf("%s lists your certificate, but the daemon does not take it yet (a reload pending?)", c.t.File))
				}
			}
			return c.cannot("asked over TCP, the daemon does not take your certificate")
		case r.down:
			view = sockAbsent // not running: the file, below
		case c.pingTimedOut(r):
			return c.cannot(c.timedOut.Error())
		default:
			if c.pin == "" {
				return c.cannot("your client certificate does not exist yet, so the daemon cannot be asked whether it takes it")
			}
			return c.cannot(c.unasked(serr, r))
		}
	}

	// The daemon is not running (its next start reads the file), or it runs
	// without the pin in force (config add enrolls and reloads it).
	if relative {
		return c.cannot(fmt.Sprintf("apiserver.access-file %q is not an absolute path, which the daemon refuses", c.t.File))
	}
	if aerr != nil {
		return c.cannot(cannotRead(c.t.File, aerr) + ", and the daemon is not running to be asked")
	}
	// A pin listed in a file the daemon would not load works no more than
	// one that is not: the daemon's own validator, as `client add` runs it.
	if err := tdns.ValidateAccessFile(af); err != nil {
		c.fileInvalid = true
		return c.cannot(invalidAccessFile(c.t.File, err))
	}
	if cl := clientByPin(af, c.pin); c.pin != "" && cl != nil {
		c.listedAs, c.listedRole = cl.Name, cl.Role
		if cl.Disabled {
			c.state = certDisabled
			return c
		}
	}
	c.addPin, c.createFile, c.nameIt = c.listedAs == "", old == nil, !c.t.Configured
	if !c.addPin && !c.createFile && !c.nameIt {
		if view == sockRunning {
			c.running, c.state = true, certCanEnable // the file has it: a reload, nothing to write
			return c
		}
		c.state = certWorks // the next start reads it
		return c
	}

	// It takes changes on the daemon's side. Can they be made from here?
	// Not tried in a dry run, which writes nothing, not even a probe: the
	// real add finds out.
	if !o.DryRun {
		if err := canReplace(c.t.File); err != nil {
			return c.cannot(fmt.Sprintf("config add cannot write %s (%v)", c.t.File, err))
		}
	}
	if c.nameIt {
		cur, err := os.ReadFile(info.ConfigFile)
		if err != nil {
			return c.cannot(cannotRead(info.ConfigFile, err))
		}
		next, err := addAccessFileLine(cur, c.t.File)
		if err != nil {
			return c.cannot(fmt.Sprintf("config add cannot add access-file: to %s (%v)", info.ConfigFile, err))
		}
		if !o.DryRun {
			if err := canReplace(info.ConfigFile); err != nil {
				return c.cannot(fmt.Sprintf("config add cannot write %s (%v)", info.ConfigFile, err))
			}
		}
		c.daemonOld, c.daemonNew = cur, next
	}
	c.running, c.state = view == sockRunning, certCanEnable
	return c
}

// sockView is what the daemon's local admin socket says.
type sockView int

const (
	sockAbsent  sockView = iota // not running: nothing on its socket (askSocket), nor on TCP (findKey)
	sockRunning                 // it answered, and runs this config
	sockShut                    // asked over TCP: the socket is not ours to use, none, or (askDaemon) silent
	sockOther                   // another daemon, or one that refused: not identified
)

// askDaemon is askSocket, except that nothing listening on the socket is
// not yet a daemon that is not running: one may run without it (started
// before its config named another socket:, say), and its access file, on
// disk, is then not the policy it runs. It is asked over TCP (sockShut), as
// when its socket is not ours to use; only nothing there either says that
// it is not running (pingReply.down).
func (c *CertSetup) askDaemon() (sockView, tdns.ConfigResponse, error) {
	view, status, serr := c.askSocket()
	if view == sockAbsent {
		if errors.Is(serr, syscall.ENOENT) {
			c.sockMissing = true
			return sockShut, status, fmt.Errorf("its local admin socket %s does not exist", c.t.Socket)
		}
		return sockShut, status, fmt.Errorf("nothing answers on its local admin socket %s", c.t.Socket)
	}
	return view, status, serr
}

// sockOtherWhy is why a daemon on the socket is not identified (sockOther),
// as a clause read after "because".
func sockOtherWhy(serr error) string {
	why := serr.Error()
	if strings.HasPrefix(why, "cannot ") {
		why = "config add " + why
	}
	return why
}

// readFile reads the access file (readAccessFile, a missing one empty),
// unless its path is relative, which the daemon refuses: nothing then.
func (c *CertSetup) readFile(relative bool) (*tdns.AccessFile, []byte, error) {
	if relative {
		return nil, nil, nil
	}
	return readAccessFile(c.t, true)
}

// findKey finds whether the daemon takes the API key (keyOff and keyWhy;
// keyUnknown when it cannot be told) from what askDaemon found: the policy
// in force (sockRunning), or a ping over TCP with the key (sockShut). It
// returns view, or sockAbsent when nothing answered on TCP either: the
// daemon is not running, and the caller asks its file (keyFromFile).
func (c *CertSetup) findKey(view sockView, status tdns.ConfigResponse, serr error) sockView {
	switch view {
	case sockRunning:
		switch a := status.Access; {
		case a == nil:
		case a.Error != "":
			c.keyOff, c.keyWhy = true, "its TCP API is closed, as it cannot use its access file"
		case !a.KeyAuth:
			c.keyOff, c.keyWhy = true, "the access file it runs turns it off (keyauth: false)"
		}
	case sockShut:
		r := c.ping(c.info, tdns.ClientOptions{AuthMethod: "X-API-Key", ApiKey: c.info.ApiKey})
		switch {
		case r.taken:
		case r.status == http.StatusServiceUnavailable:
			c.keyOff, c.keyWhy = true, "its TCP API is closed, as it cannot use its access file"
		case r.answered:
			c.keyOff, c.keyWhy = true, "asked over TCP, it refuses the key"
		case r.down:
			return sockAbsent // nothing on its socket we may open, nothing on TCP: not running
		case c.pingTimedOut(r):
			c.keyUnknown = c.timedOut.Error()
		default:
			c.keyUnknown = c.unasked(serr, r)
		}
	}
	return view
}

// recheckKey finds again whether the daemon takes the API key, as planCert
// did: after an apply that sent a reload and failed, the rollback reloaded
// the daemon with the files put back, so the policy it runs may not be the
// one planCert asked (a keyauth: false that was in the file, but not yet in
// force, is in force now).
func (c *CertSetup) recheckKey() {
	c.keyOff, c.keyWhy, c.keyUnknown = false, "", ""
	relative := c.t.Configured && !filepath.IsAbs(c.t.File)
	af, old, aerr := c.readFile(relative)
	view, status, serr := c.askDaemon()
	if view == sockOther {
		c.keyUnknown = sockOtherWhy(serr)
		return
	}
	if c.findKey(view, status, serr) == sockAbsent {
		c.keyFromFile(relative, old, af, aerr)
	}
}

// invalidAccessFile is why access file file, which err says the daemon would
// not load, does not let a certificate work, as a clause.
func invalidAccessFile(file string, err error) string {
	return fmt.Sprintf("%s is not an access file the daemon would load (%v)", file, err)
}

// askSocket asks the daemon on its local admin socket which config it runs,
// and the policy in force. A daemon that does not answer in time
// (sendBounded) is not identified either (sockOther), the timeout the error.
func (c *CertSetup) askSocket() (sockView, tdns.ConfigResponse, error) {
	if c.t.Socket == "" {
		return sockShut, tdns.ConfigResponse{}, errors.New("it serves no local admin socket")
	}
	resp, err := sendBounded(tdns.NewClient(c.role, "unix://"+c.t.Socket, "", "none", ""), tdns.ConfigPost{Command: "status"})
	switch {
	case err == nil:
		if rerr := runsConfig(resp, c.t); rerr != nil {
			return sockOther, resp, rerr
		}
		return sockRunning, resp, nil
	case nothingListening(err):
		return sockAbsent, resp, err // which: no socket file, or a refused connection
	case errors.Is(err, os.ErrPermission):
		return sockShut, resp, fmt.Errorf("its local admin socket %s is not ours to open", c.t.Socket)
	case daemonTimedOut(err):
		return sockOther, resp, err
	}
	return sockOther, resp, fmt.Errorf("cannot ask the daemon on %s which config it runs (%v)", c.t.Socket, err)
}

// ping pings the daemon's TCP API with o's credentials, the daemon verified
// by the pin of its certificate (daemonTCP). When it cannot be asked so (no
// TLS TCP API, or a certificate that cannot be pinned, as before a daemon's
// first start writes it), down still says whether nothing listens on its
// TCP address: a daemon that is not running.
func (c *CertSetup) ping(info *DaemonApi, o tdns.ClientOptions) pingReply {
	base, pin, err := daemonTCP(info)
	if err != nil {
		return pingReply{err: err, down: tcpRefused(info)}
	}
	r := pingAs(base, pin, o)
	r.base = base
	return r
}

// unasked says why the daemon could not be asked: not on its socket (serr),
// and not over TCP (r).
func (c *CertSetup) unasked(serr error, r pingReply) string {
	tcp := "no TCP API to ask"
	switch {
	case r.base != "" && r.err != nil:
		tcp = fmt.Sprintf("no answer on %s (%v)", r.base, r.err)
	case r.base != "":
		tcp = "no answer on " + r.base
	case r.err != nil:
		tcp = r.err.Error()
	}
	return fmt.Sprintf("the daemon cannot be asked: %v, and over TCP, %s", serr, tcp)
}

// keyFromFile is whether the daemon takes the key, by its access file: for a
// daemon that is not running, whose next start reads it. Without one named
// in the daemon config the key works (admin), whatever a file at the
// suggested path says: the daemon does not read it.
func (c *CertSetup) keyFromFile(relative bool, old []byte, af *tdns.AccessFile, aerr error) {
	switch {
	case !c.t.Configured:
	case relative:
		c.keyUnknown = fmt.Sprintf("apiserver.access-file %q is not an absolute path", c.t.File)
	case aerr != nil:
		c.keyUnknown = cannotRead(c.t.File, aerr) + ", and the daemon is not running to be asked"
	case old == nil:
		c.keyOff, c.keyWhy = true, fmt.Sprintf("%s, which the daemon config names, does not exist (the daemon closes its TCP API then)", c.t.File)
	case tdns.ValidateAccessFile(af) != nil:
		c.keyOff, c.keyWhy = true, fmt.Sprintf("%s, which the daemon config names, is not an access file it would load (it closes its TCP API then)", c.t.File)
	case !af.KeyAuthOn():
		c.keyOff, c.keyWhy = true, fmt.Sprintf("%s turns it off (keyauth: false)", c.t.File)
	}
}

// daemonTCP is the daemon's TCP API (its first address) and the pin of the
// certificate it presents there: how config add asks it, verified, when it
// cannot read the daemon's access file.
func daemonTCP(info *DaemonApi) (string, string, error) {
	if len(info.Addresses) == 0 || !info.UseTLS {
		return "", "", errors.New("it has no TLS TCP API")
	}
	base, err := apiBaseURL(info.Addresses[0], true)
	if err != nil {
		return "", "", err
	}
	pin, err := daemonCertPin(info)
	if err != nil {
		return "", "", err
	}
	return base, pin, nil
}

// tcpRefused says whether the daemon's TCP API (its first address) refuses
// a connection: nothing listens there.
func tcpRefused(info *DaemonApi) bool {
	if len(info.Addresses) == 0 {
		return false
	}
	base, err := apiBaseURL(info.Addresses[0], info.UseTLS)
	if err != nil {
		return false
	}
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err == nil {
		conn.Close()
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// pingReply is what a daemon's TCP API said to a ping: taken (pr says with
// which role, how and as whom), refused (401, 403) or closed (503) when
// answered without taken, or no answer at all.
type pingReply struct {
	answered, taken bool
	down            bool // the TCP connection was refused: nothing listens there
	status          int
	pr              tdns.PingResponse
	base            string // where it was asked
	err             error  // why there was no answer
}

// pingLimit bounds config add's ping of a daemon's TCP API (pingAs); a
// variable, which tests shorten.
var pingLimit = 5 * time.Second

// pingTimedOut says whether r is a ping the daemon did not answer within
// pingLimit, and if so takes it for c's (timedOut): a daemon silent on TCP
// is wedged, as one silent on its socket is, with the same verdict and fix.
func (c *CertSetup) pingTimedOut(r pingReply) bool {
	var te *daemonTimeoutError
	if !errors.As(r.err, &te) {
		return false
	}
	c.timedOut = te
	return true
}

// pingAs pings the TCP API at base, the daemon verified by pin, with the
// credentials in o: the client certificate, or the API key. A daemon that
// does not answer within pingLimit is a *daemonTimeoutError, as for
// sendBounded.
func pingAs(base, pin string, o tdns.ClientOptions) pingReply {
	o.Pins = []string{pin}
	api := tdns.NewClientWithOptions("config add", base, o)
	body, err := json.Marshal(tdns.PingPost{Msg: "config add", Pings: 1})
	if err != nil {
		return pingReply{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), pingLimit)
	defer cancel()
	var connected atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				connected.Store(true)
			}
		},
	})
	status, buf, err := api.PostContext(ctx, "/ping", body)
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = &daemonTimeoutError{where: daemonWhere(api), command: "ping", limit: pingLimit, connected: connected.Load()}
	}
	r := pingReply{status: status, err: err, down: errors.Is(err, syscall.ECONNREFUSED)}
	switch {
	case err == nil && status == http.StatusOK:
		r.answered = true
		r.taken = json.Unmarshal(buf, &r.pr) == nil
	case status == http.StatusUnauthorized, status == http.StatusForbidden, status == http.StatusServiceUnavailable:
		r.answered, r.err = true, nil
	}
	return r
}

// testHookRollbackRestore, when set, runs in rollback for each file it is
// about to put back: after it found the file still holds what apply wrote,
// before the restore, with the file's lock held. A test tries a concurrent
// edit there, in the window one could otherwise slip into. Tests only.
var testHookRollbackRestore func(path string)

// lockPaths are the files apply, rollback and confirm lock (lockCliConfigs,
// which takes each lock once and all in one order): the access file, whose
// lock every `client` edit takes too; and the daemon config when apply adds
// access-file: to it. Apply is the only writer of the daemon config here,
// so its lock is the daemon config's own, as for any file config add edits:
// two adds that reach one daemon config through two paths (a symlink) wait
// for each other on it, though they suggest two access files. A hand edit
// takes no lock; rollback's compare is all that protects it.
func (c *CertSetup) lockPaths() []string {
	if c.nameIt {
		return []string{c.t.File, c.t.DaemonConfig}
	}
	return []string{c.t.File}
}

// apply makes the daemon accept the certificate: the pin added to the access
// file (created if need be), the file named in the daemon config if it was
// not, and the daemon reloaded over its local socket when it runs, the
// running policy then checked for the pin. Each step as `client add` takes it
// (the access file's lock, the daemon's own validator, the write with .prev,
// the check of whose daemon answers); the daemon config is written the way
// the access file is, under its own lock, its old bytes kept as .prev and
// the new file renamed over it with its owner, group and mode.
//
// The locks (lockPaths) are held from the reads on. A step that fails puts
// back what the steps before it changed and reloads the daemon with the
// files put back, still under them, and then releases them (undoLocked;
// the .prev files stay); c.failed is set to why. After a success they stay
// held (c.held) until the caller has written the CLI config (release) or
// put the daemon's side back (rollback): until then the enrolment may yet
// be put back, so another add must not rely on it, and waits for them
// (confirm).
func (c *CertSetup) apply(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	unlock, err := lockCliConfigs(ctx, c.lockPaths()...)
	if err != nil {
		c.failed = err
		return err
	}
	if err = c.applySteps(); err != nil {
		// A daemon that did not answer in time: a failed step like any
		// other, put back below; the fix is about the daemon.
		errors.As(err, &c.timedOut)
		// Put back under the locks apply holds: rollback would take them
		// again, and a second flock in this process waits for the first.
		err = fmt.Errorf("%v; %s", err, c.undoLocked(unlock))
	} else {
		c.held = unlock
	}
	c.failed = err
	return err
}

// release releases the locks a successful apply, or confirm, kept (held):
// for a caller that has written the CLI config, or will not. Nil-safe, and
// a no-op when nothing is held (after a rollback, say).
func (c *CertSetup) release() {
	if c != nil && c.held != nil {
		c.held()
		c.held = nil
	}
}

// confirm is for an add about to write a CLI entry that relies on the
// certificate working as planCert found it, with nothing for config add to
// do (certWorks): an enrolment in the access file, or in force, that this
// add did not make. It may be another add's, not yet kept: that add may
// still fail to write its CLI config and put the enrolment back, its file
// still holding just what it wrote. So confirm takes the locks such an add
// holds from its writes until it has written its CLI config or put the
// daemon's side back, the reload included (apply, rollback), and plans
// again under them: the daemon config must say what it said, and the
// certificate must still work. An enrolment found so is no add's to put
// back, as a rollback puts back only what its own add wrote, and does so
// before it lets go of the locks. They stay held (c.held) until the caller
// has written the CLI config (release), so none is made meanwhile either.
//
// The enrolment must also be one that lasts: listed, enabled, in the access
// file the daemon config names. One only in force (a rollback took it out
// of the file and its reload failed, or a `client remove --no-reload` is
// pending) is gone at the daemon's next reload or start, and the entry with
// it.
//
// When the plan no longer holds, c can no longer work as planned (not
// usable(): changed, or the enrolment not in the file, with its key verdict
// as found again), and the caller does not write the entry; the error is
// only for locks that could not be taken. A lock this process may not take
// (not root: the lock file is the daemon's) is gone without, and so is a
// file it may not read: such an add relies on what the daemon says over
// TCP, and cannot enrol, nor put back, anything itself.
func (c *CertSetup) confirm(o AddOptions) error {
	if c.state != certWorks || c.held != nil {
		return nil
	}
	ctx := o.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	unlock, err := lockCliConfigs(ctx, c.lockPaths()...)
	switch {
	case errors.Is(err, fs.ErrPermission), errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	}
	// Planned again from the daemon config as it is now, which must say
	// what it said: the access file it names and the API the entry is for.
	var again *CertSetup
	same := false
	if now, err := ReadDaemonApi(c.t.DaemonConfig, c.role); err == nil {
		again = planCert(o, now, c.word)
		same = now.AccessFile == c.info.AccessFile && sameApiApartFromAccess(c.info, now)
	}
	if !same || again.state != certWorks || again.pin != c.pin {
		unlock()
		c.cannot("what config add found on the daemon's side changed while it ran (another config add put back what it had enrolled?)")
		c.changed = true
		if again != nil {
			c.keyOff, c.keyWhy, c.keyUnknown = again.keyOff, again.keyWhy, again.keyUnknown
			if again.timedOut != nil {
				// Not a change: the daemon no longer answers.
				c.cannot(again.why)
				c.timedOut = again.timedOut
			}
		}
		return nil
	}
	if why := again.notInFile(); why != "" {
		unlock()
		// Not listed where it lasts: the fix is to enrol it there.
		c.cannot(why)
		c.listedAs, c.listedRole, c.byDaemon = "", "", false
		c.keyOff, c.keyWhy, c.keyUnknown = again.keyOff, again.keyWhy, again.keyUnknown
		return nil
	}
	c.held = unlock
	return nil
}

// notInFile says why the pin, which the daemon takes, is not enrolled in
// the access file it reads at its next reload or start: the daemon config
// names none, or the file does not list the pin, enabled. "" when it does,
// or when this process may not read the file (not root).
func (c *CertSetup) notInFile() string {
	if !c.t.Configured {
		return fmt.Sprintf("the daemon takes your certificate now, but %s names no access file, so it will not after its next start", c.t.DaemonConfig)
	}
	af, _, err := readAccessFile(c.t, false)
	switch {
	case errors.Is(err, fs.ErrPermission):
		return ""
	case err != nil:
		return fmt.Sprintf("the daemon takes your certificate, but %s", cannotRead(c.t.File, err))
	}
	if cl := clientByPin(af, c.pin); cl == nil || cl.Disabled {
		return fmt.Sprintf("the daemon takes your certificate now, but %s does not list it, enabled, so it will not after its next reload or start", c.t.File)
	}
	return ""
}

// applySteps is apply's work. The caller holds the locks (lockPaths).
func (c *CertSetup) applySteps() error {
	// The daemon config must still name what it named when config add read
	// it: an operator may have pointed it at another access file since, and
	// enrolling the pin in this one would then do nothing.
	now, err := ReadDaemonApi(c.t.DaemonConfig, c.role)
	if err != nil {
		return err
	}
	if planned := map[bool]string{true: c.t.File, false: ""}[c.t.Configured]; now.AccessFile != planned {
		c.changed = true
		return fmt.Errorf("%s now names access-file %q, not %q as when config add read it; run config add again", c.t.DaemonConfig, now.AccessFile, planned)
	}
	// Nor anything else about its API, which the entry is made from: a
	// daemon moved to another port meanwhile would be enrolled all the
	// same, and the entry written for the old one.
	if !sameApiApartFromAccess(c.info, now) {
		c.changed = true
		return fmt.Errorf("%s now has other apiserver: settings than when config add read it; run config add again", c.t.DaemonConfig)
	}

	// Again under the lock: a `client` edit may have changed it since.
	af, old, err := readAccessFile(c.t, true)
	if err != nil {
		return err
	}
	// Whether or not the pin is added: listed in a file the daemon would
	// not load, it does not work, and naming the file or reloading the
	// daemon would only close its TCP API.
	if err := tdns.ValidateAccessFile(af); err != nil {
		return errors.New(invalidAccessFile(c.t.File, err))
	}
	var accessNew []byte
	if cl := clientByPin(af, c.pin); cl != nil {
		if cl.Disabled {
			return fmt.Errorf("%s now lists your certificate as %q, disabled", c.t.File, cl.Name)
		}
		c.listedAs, c.listedRole = cl.Name, cl.Role
	} else {
		name := freeName(c.name, func(n string) bool { return findClient(af, n) != nil })
		af.Clients = append(af.Clients, tdns.AccessClient{Name: name, Pin: c.pin, Role: "read-write"})
		if err := tdns.ValidateAccessFile(af); err != nil {
			return fmt.Errorf("not writing %s: %v", c.t.File, err)
		}
		if accessNew, err = renderAccessFile(af, c.t.DaemonConfig); err != nil {
			return err
		}
		c.enrolledAs = name
	}
	c.createFile = old == nil

	// The daemon that answers on the socket must be this config's, right
	// before anything is written (verifyRunningDaemon's check).
	if c.running, err = socketDaemon(c.role, c.t); err != nil {
		return err
	}

	if accessNew != nil {
		if err := writeAccessFile(c.t.File, old, accessNew, c.t.DaemonConfig); err != nil {
			return err
		}
		c.undo = append(c.undo, fileUndo{path: c.t.File, wrote: accessNew, old: old})
	}

	if c.nameIt {
		cur, err := os.ReadFile(c.t.DaemonConfig)
		if err != nil {
			return err
		}
		next := c.daemonNew
		if !bytes.Equal(cur, c.daemonOld) {
			if next, err = addAccessFileLine(cur, c.t.File); err != nil {
				return fmt.Errorf("cannot add access-file: to %s (%v)", c.t.DaemonConfig, err)
			}
		}
		// As the access file is written (writeAccessFile), under the
		// daemon config's own lock (lockPaths): the old bytes kept as
		// .prev first, then the new file renamed over the config, with its
		// owner, group and mode. A rollback puts the old bytes back the
		// same way, under the same lock, and leaves the .prev.
		if err := writeFileAtomic(c.t.DaemonConfig+".prev", cur); err != nil {
			return fmt.Errorf("saving %s.prev: %w", c.t.DaemonConfig, err)
		}
		if err := writeFileAtomicLike(c.t.DaemonConfig, next, nil); err != nil {
			return err
		}
		c.undo = append(c.undo, fileUndo{path: c.t.DaemonConfig, wrote: next, old: cur})
		// Read back the way config add read it: the daemon must now name
		// this access file, and say everything else as it did.
		after, err := ReadDaemonApi(c.t.DaemonConfig, c.role)
		if err != nil || !sameApiApartFromAccess(c.info, after) || after.AccessFile != c.t.File {
			return fmt.Errorf("%s does not read back as before plus access-file: %s (does an include: file set apiserver:?)", c.t.DaemonConfig, c.t.File)
		}
	}

	// Asked again now the files are written: a daemon that started since
	// the check above read the old ones, and needs the reload too.
	if !c.running {
		if c.running, err = socketDaemon(c.role, c.t); err != nil {
			return err
		}
		if !c.running {
			return nil // the next start reads the files
		}
	}
	c.didReload, c.reloadSent = true, true
	msg, err := reloadAccess(c.role, c.t)
	if err != nil {
		return err
	}
	if err := c.inForce(); err != nil {
		return err
	}
	c.reloaded = msg
	return nil
}

// rollback puts back what apply changed, after apply returned, and says how
// that went: each file as it was before (removed, if apply created it),
// unless it has changed since apply wrote it, which is then left as it is;
// and, when apply reloaded the daemon, a reload over its socket so that it
// runs the files as they are again, checked by asking it what it runs. The
// .prev files stay. Done at most once.
//
// The files are compared and put back, and the daemon reloaded, under the
// locks apply took (lockPaths) and kept (c.held), which are then released;
// were they released already, they are taken again, ctx ending the wait. A
// `client` edit, or another config add, that comes between the compare and
// the restore waits, and is made on the file put back, rather than lost to
// it; and another add that would rely on the enrolment (confirm) finds the
// daemon as it was, the reload included. Never called while apply is still
// running (apply puts back with undoLocked).
func (c *CertSetup) rollback(ctx context.Context) string {
	unlock := c.held
	c.held = nil
	if unlock == nil {
		unlock = func() {}
		if len(c.undo) > 0 {
			if ctx == nil {
				ctx = context.Background()
			}
			u, err := lockCliConfigs(ctx, c.lockPaths()...)
			if err != nil {
				c.undo = nil
				return c.reloadBack(fmt.Sprintf("putting the files back FAILED (%v): check %s and %s by hand", err, c.t.File, c.t.DaemonConfig))
			}
			unlock = u
		}
	}
	return c.undoLocked(unlock)
}

// undoLocked is rollback for a caller that holds the locks (lockPaths): the
// files put back, the daemon reloaded with them, and then the locks
// released (unlock).
func (c *CertSetup) undoLocked(unlock func()) string {
	defer unlock()
	if len(c.undo) == 0 && !c.didReload {
		return "nothing on the daemon's side was changed"
	}
	return c.reloadBack(c.restoreFiles())
}

// restoreFiles puts back the files apply wrote, the last first, and says
// how that went. The caller holds their locks.
func (c *CertSetup) restoreFiles() string {
	var left, failed []string
	for i := len(c.undo) - 1; i >= 0; i-- {
		u := c.undo[i]
		cur, err := os.ReadFile(u.path)
		switch {
		case err != nil && !(u.old == nil && errors.Is(err, fs.ErrNotExist)):
			failed = append(failed, err.Error())
		case err == nil && !bytes.Equal(cur, u.wrote):
			left = append(left, u.path)
		case err == nil:
			if testHookRollbackRestore != nil {
				testHookRollbackRestore(u.path)
			}
			if u.old == nil {
				if rerr := os.Remove(u.path); rerr != nil {
					failed = append(failed, rerr.Error())
				}
			} else if werr := writeFileAtomicLike(u.path, u.old, nil); werr != nil {
				failed = append(failed, werr.Error())
			}
		}
	}
	c.undo = nil
	switch {
	case len(failed) > 0:
		return fmt.Sprintf("putting the files back FAILED (%s): check %s and %s by hand", strings.Join(failed, "; "), c.t.File, c.t.DaemonConfig)
	case len(left) > 0:
		return fmt.Sprintf("the files are put back, except %s, changed since config add wrote it, and left as it is", strings.Join(left, " and "))
	}
	return "the files are as they were"
}

// reloadBack ends a rollback whose files went as files says: when apply
// reloaded the daemon, it is reloaded again, so that it runs the files as
// they are now. Done under the files' locks (undoLocked), unless they could
// not be taken.
func (c *CertSetup) reloadBack(files string) string {
	if !c.didReload {
		return files
	}
	c.didReload = false
	var sb strings.Builder
	sb.WriteString(files)
	// The daemon was reloaded with the new files: it must run the old ones
	// again.
	if _, err := reloadAccess(c.role, c.t); err != nil {
		fmt.Fprintf(&sb, "; the daemon could NOT be reloaded with them (%v): it may still run the new policy, reload it over its socket", err)
		return sb.String()
	}
	resp, err := configToDaemon(c.role, c.t.Socket, c.t.DaemonConfig, tdns.ConfigPost{Command: "status"})
	switch {
	case err != nil:
		fmt.Fprintf(&sb, "; the daemon was reloaded with them, but what it runs now could not be asked (%v)", err)
	case resp.Access != nil && (c.nameIt || c.enrolledAs != "" && policyHasPin(resp.Access, c.pin)):
		sb.WriteString("; the daemon was reloaded with them, but it still runs the new policy: check it")
	default:
		sb.WriteString(", and the daemon runs them again")
	}
	return sb.String()
}

// cannotRead is why config add cannot use file, as a clause: the cause of a
// file-system error (permission denied) rather than its whole text, which
// repeats the path.
func cannotRead(file string, err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return fmt.Sprintf("config add cannot read %s (%v)", file, pe.Err)
	}
	return err.Error()
}

// sameApiApartFromAccess says whether a and b, two reads of one daemon
// config, say the same about its API, the access file aside.
func sameApiApartFromAccess(a, b *DaemonApi) bool {
	return a.ConfigFile == b.ConfigFile && reflect.DeepEqual(a.Addresses, b.Addresses) &&
		a.ApiKey == b.ApiKey && a.Socket == b.Socket && a.CertFile == b.CertFile && a.UseTLS == b.UseTLS
}

// policyHasPin says whether the running policy a has pin, enabled.
func policyHasPin(a *tdns.ApiAccessStatus, pin string) bool {
	for _, cl := range a.Clients {
		if cl.Pin == pin && !cl.Disabled {
			return true
		}
	}
	return false
}

// inForce checks that the daemon runs a policy in which the pin is enabled.
func (c *CertSetup) inForce() error {
	resp, err := configToDaemon(c.role, c.t.Socket, c.t.DaemonConfig, tdns.ConfigPost{Command: "status"})
	if err != nil {
		return fmt.Errorf("reloaded, but asking the daemon what it runs failed: %w", err)
	}
	if err := runsConfig(resp, c.t); err != nil {
		return err
	}
	a := resp.Access
	switch {
	case a == nil:
		return errors.New("reloaded, but the daemon runs no access file")
	case a.Error != "":
		return fmt.Errorf("reloaded, but the daemon cannot use its access file: %s", a.Error)
	case !policyHasPin(a, c.pin):
		return errors.New("reloaded, but the policy the daemon runs does not have your certificate")
	}
	return nil
}

// canReplace says whether this process may replace path the way the writes
// do (writeFileAtomicLike): create a file in its directory, give it the old
// file's owner, and rename it over the old one. The directory is tried with a
// file created and removed at once.
func canReplace(path string) error {
	real := resolvedPath(path)
	f, err := os.CreateTemp(filepath.Dir(real), ".tdns-ncli-probe-*")
	if err != nil {
		// The cause, not the probe's made-up name.
		var pe *os.PathError
		if errors.As(err, &pe) {
			return pe.Err
		}
		return err
	}
	f.Close()
	os.Remove(f.Name())
	if fi, err := os.Stat(real); err == nil {
		if uid, _, ok := fileOwner(fi); ok && uid != os.Geteuid() && os.Geteuid() != 0 {
			return fmt.Errorf("%s belongs to another user", path)
		}
	}
	return nil
}

// reClientName is a certificate CN usable as an access-file name as it
// stands.
var reClientName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// clientNameOf is the name the access file gets for the certificate in file
// cert: its CN, if it has one fit to be a name, else defaultClientName().
func clientNameOf(cert string) string {
	if data, err := os.ReadFile(cert); err == nil {
		for {
			var b *pem.Block
			if b, data = pem.Decode(data); b == nil {
				break
			}
			if b.Type != "CERTIFICATE" {
				continue
			}
			if c, err := x509.ParseCertificate(b.Bytes); err == nil && reClientName.MatchString(c.Subject.CommonName) {
				return c.Subject.CommonName
			}
			break
		}
	}
	return defaultClientName()
}

// ------------------------------------------------- the daemon config's line

var (
	reApiserverBlock = regexp.MustCompile(`^apiserver:[ \t]*(#.*)?$`)
	reApiserverAny   = regexp.MustCompile(`^apiserver:`)
)

// addAccessFileLine returns the daemon config src with "access-file: path"
// added to its apiserver: block: after the block's last line, at the column
// of its keys, the value aligned like the block's first key. Nothing else in
// the file changes, comments, order and indentation included. It refuses a
// file it cannot edit with confidence: no block-style apiserver: key in the
// file itself (it may be in an include: file), two of them, tabs, an
// access-file: line already there. The result is checked: read as YAML, it is
// src with that one key added.
func addAccessFileLine(src []byte, path string) ([]byte, error) {
	lines := strings.Split(string(src), "\n")
	start := -1
	for i, l := range lines {
		l = strings.TrimRight(l, "\r")
		switch {
		case reApiserverBlock.MatchString(l):
			if start >= 0 {
				return nil, errors.New("it has two apiserver: keys")
			}
			start = i
		case reApiserverAny.MatchString(l):
			return nil, errors.New("its apiserver: is written inline (flow style)")
		}
	}
	if start < 0 {
		return nil, errors.New("its apiserver: block is not in the file itself (in an include: file?)")
	}
	last := apiserversBlockEnd(lines, start)

	keyCol, valueCol := -1, 0
	for j := start + 1; j <= last; j++ {
		l := strings.TrimRight(lines[j], "\r")
		body := strings.TrimLeft(l, " ")
		if body == "" || strings.HasPrefix(body, "#") {
			continue
		}
		if strings.HasPrefix(body, "\t") {
			return nil, errors.New("its apiserver: block is indented with tabs")
		}
		ind := len(l) - len(body)
		m := reKeyLine.FindStringSubmatch(body)
		if keyCol < 0 {
			if m == nil {
				return nil, errors.New("its apiserver: block does not start with a key")
			}
			keyCol = ind
			// Aligned like the first key when it is aligned with spaces;
			// otherwise one space after the colon.
			pad := len(m[2]) - len(strings.TrimLeft(m[2], " "))
			if pad >= 2 && !strings.HasPrefix(strings.TrimLeft(m[2], " "), "\t") {
				valueCol = len(m[1]) + 1 + pad
			}
		}
		if ind == keyCol && m != nil && strings.EqualFold(m[1], "access-file") {
			return nil, errors.New("its apiserver: block has an access-file: line already")
		}
	}
	if keyCol < 0 {
		return nil, errors.New("its apiserver: block is empty")
	}

	add := kvLine(keyCol, valueCol, "access-file", yamlScalar(path))
	if strings.HasSuffix(lines[last], "\r") {
		add += "\r"
	}
	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:last+1]...)
	out = append(out, add)
	out = append(out, lines[last+1:]...)
	res := []byte(strings.Join(out, "\n"))

	// Read back: the same document, plus apiserver.access-file.
	var before, after map[string]interface{}
	if err := yaml.Unmarshal(src, &before); err != nil {
		return nil, fmt.Errorf("it does not parse as YAML (%v)", err)
	}
	if err := yaml.Unmarshal(res, &after); err != nil {
		return nil, fmt.Errorf("the edited file would not parse (%v)", err)
	}
	api, _ := after["apiserver"].(map[string]interface{})
	if got, _ := api["access-file"].(string); got != path {
		return nil, errors.New("the edited file does not read back with that access-file:")
	}
	delete(api, "access-file")
	if !reflect.DeepEqual(before, after) {
		return nil, errors.New("the edited file reads back changed in more than that line")
	}
	return res, nil
}

// ---------------------------------------------------------------- printing

// fixLines say what makes the certificate work when config add could not.
func (c *CertSetup) fixLines() []string {
	switch {
	case c.timedOut != nil:
		// Asking it again does not help while it is wedged; whatever apply
		// wrote is put back, so config add plans anew.
		return []string{daemonWedgedFix + ";", "then run config add again."}
	case c.changed:
		return []string{"run config add again."}
	case c.sockGone:
		return []string{
			"restart the daemon: it makes its local admin socket " + c.t.Socket,
			"when it starts, and reads its access file again;",
			"then run config add again.",
		}
	case c.unidentified:
		return c.sockFixLines()
	case c.noTLS:
		return []string{
			"turn on TLS for the daemon's TCP API (apiserver.usetls: true,",
			"with certfile and keyfile), then run config add again.",
		}
	case c.noSocket:
		return []string{
			"give the daemon its local admin socket (leave apiserver.socket",
			"out for the default, or give it an absolute path; not none),",
			"restart the daemon, then run config add again.",
		}
	case c.state == certDisabled:
		return []string{
			"on the daemon's host, as root:",
			"   tdns-ncli " + c.word + " client enable " + shellQuote(c.listedAs),
			"then run config add again.",
		}
	case c.pairProblem != 0:
		return c.pairFixLines()
	case c.fileInvalid:
		return []string{
			"fix " + c.t.File + " so the daemon would load it",
			"(the error says what), then run config add again.",
		}
	}
	if c.listedAs != "" {
		// The pin is there already: what is left is the daemon reading it.
		if !c.t.Configured {
			return []string{
				"on the daemon's host, as root, add under apiserver: in " + c.t.DaemonConfig + ":",
				"   access-file: " + yamlScalar(c.t.File),
				"and reload the daemon; then run config add again.",
			}
		}
		return []string{
			"on the daemon's host, as root:",
			"   tdns-ncli " + c.word + " config reload",
			"then run config add again.",
		}
	}
	if c.pin == "" {
		// A dry run, before the pair exists: there is no pin to name yet.
		return []string{
			"your client certificate does not exist yet, so it has no pin",
			"to enrol; config add makes it when run without --dry-run,",
			"and then says how to enrol it.",
		}
	}
	lines := []string{
		"on the daemon's host, as root:",
		fmt.Sprintf("   tdns-ncli %s client add %s --pin %s --role read-write", c.word, shellQuote(c.name), c.pin),
	}
	if !c.t.Configured {
		lines = append(lines,
			"and add under apiserver: in "+c.t.DaemonConfig+":",
			"   access-file: "+yamlScalar(c.t.File),
			"and reload the daemon; then run config add again.")
	} else {
		lines = append(lines, "then run config add again.")
	}
	return lines
}

// sockFixLines say what makes config add able to tell that the daemon on
// the local admin socket is this one, when it could not (unidentified):
// until it can, enrolling the pin does not help, as another daemon may
// answer there.
func (c *CertSetup) sockFixLines() []string {
	switch o := c.other; {
	case o != nil && o.runs != "":
		return []string{
			"stop the daemon that runs " + o.runs + ",",
			"or give " + o.runs + " and " + o.want,
			"their own admin socket and API addresses",
			"(apiserver.socket, apiserver.addresses);",
			"then run config add again.",
		}
	case o != nil:
		return []string{
			"stop the daemon that answers on " + c.t.Socket + " if it does",
			"not run " + o.want + ", or give the two configs their own",
			"admin socket and API addresses; if it does, upgrade it so it",
			"says which config it runs; then run config add again.",
		}
	}
	return []string{
		"fix what stops the daemon on " + c.t.Socket + " saying",
		"which config it runs (the error says what);",
		"then run config add again.",
	}
}

// pairFixLines say what makes the operator's own pair usable, when it is
// not: until it is, there is no pin to enrol. config add makes a new pair
// when neither file is there, and never overwrites one that is.
func (c *CertSetup) pairFixLines() []string {
	switch c.pairProblem {
	case pairKeyOnly:
		return []string{
			"put back your certificate " + c.cert + ",",
			"or remove your key " + c.key + " so config add makes a new pair;",
			"then run config add again.",
		}
	case pairNoMatch:
		return []string{
			"make your certificate " + c.cert + " and your key " + c.key + " one pair again,",
			"or remove both so config add makes a new pair;",
			"then run config add again.",
		}
	case pairBadCert:
		return []string{
			"fix your certificate " + c.cert + " so it can be read,",
			"or remove it and your key " + c.key + " so config add makes a new pair;",
			"then run config add again.",
		}
	}
	return []string{
		"fix what stops config add reading or making your pair,",
		c.cert + " and " + c.key + " (the error says what);",
		"then run config add again.",
	}
}

// listedEnrollment is how the access file lists the pin: its name and its
// role, said plainly when it is read-only. config add does not change an
// enrollment it finds, so a read-only one stays read-only.
func (c *CertSetup) listedEnrollment() string {
	switch c.listedRole {
	case "read-only":
		return c.listedAs + ", read-only: write commands will be refused (tdns-ncli " + c.word + " client set-role " + shellQuote(c.listedAs) + " read-write changes that)"
	case "":
		return c.listedAs
	}
	return c.listedAs + " (" + c.listedRole + ")"
}

// whyNot is the one-line reason the certificate does not work.
func (c *CertSetup) whyNot() string {
	switch {
	case c.failed != nil:
		return c.failed.Error()
	case c.state == certDisabled:
		return fmt.Sprintf("%s lists your certificate as %q, disabled, and config add does not enable it", c.t.File, c.listedAs)
	}
	return c.why
}

// addRefusal is a config add that does not go ahead: why, and what fixes it.
// The command prints it as a refusal, with the fix on lines of its own.
type addRefusal struct {
	why   string
	notes []string // said between the why and the fix
	fix   []string
}

// refusal is a refusal for why, with what makes the certificate work as its
// fix, and saying so when the operator's pair was made on the way.
func (c *CertSetup) refusal(why string) addRefusal {
	r := addRefusal{why: why, fix: c.fixLines()}
	if c.pairNew && c.pin != "" {
		r.notes = []string{"Created your client certificate " + c.cert + "; its pin is in the fix."}
	}
	return r
}

func (r addRefusal) Error() string {
	fix := make([]string, len(r.fix))
	for i, l := range r.fix {
		fix[i] = strings.TrimSpace(l)
	}
	return r.why + "; fix: " + strings.Join(fix, " ")
}

// printRefusal prints r as a refusal, the way dieOn does: the why, then the
// fix on lines of its own, wrapped to textWidth.
func printRefusal(w io.Writer, r addRefusal) {
	writeWrapped(w, "Error: ", "  ", r.why+".")
	for _, n := range r.notes {
		writeWrapped(w, "  ", "  ", n)
	}
	writeFix(w, "", "  Fix: ", "       ", r.fix)
}

// textWidth is the widest line config add prints, when no single word (a
// path, a pin) is wider.
const textWidth = 72

// writeWrapped writes segments as one paragraph: the first line begins with
// first and every other line with rest; each segment begins a new line, and
// one too long for a line is wrapped at its spaces. A word too wide for any
// line (a path) stays on the line it would begin, rather than leave a short
// word alone on the line before it.
func writeWrapped(w io.Writer, first, rest string, segments ...string) {
	prefix := first
	emit := func(line string) {
		fmt.Fprintf(w, "%s%s\n", prefix, line)
		prefix = rest
	}
	for _, seg := range segments {
		line := ""
		for _, word := range strings.Fields(seg) {
			switch {
			case line == "":
				line = word
			case len(prefix)+len(line)+1+len(word) <= textWidth, len(rest)+len(word) > textWidth:
				line += " " + word
			default:
				emit(line)
				line = word
			}
		}
		if line != "" {
			emit(line)
		}
	}
}

// writeFix writes fix lines (CertSetup.fixLines) after lead: each run of
// prose joined and wrapped, the first beginning with lead; command and config
// lines (indented three spaces) as they stand. The first line begins with
// first, every other with rest.
func writeFix(w io.Writer, lead, first, rest string, lines []string) {
	prefix := first
	var prose []string
	if lead != "" {
		prose = append(prose, lead)
	}
	flush := func() {
		if len(prose) > 0 {
			writeWrapped(w, prefix, rest, strings.Join(prose, " "))
			prefix, prose = rest, nil
		}
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "   ") {
			flush()
			fmt.Fprintf(w, "%s%s\n", prefix, l)
			prefix = rest
			continue
		}
		prose = append(prose, l)
	}
	flush()
}

// writeTrouble writes why the certificate does not work, as one paragraph
// beginning with head, and then what would make it work.
func (c *CertSetup) writeTrouble(w io.Writer, head string, keyKept bool) {
	reason := ", because " + c.whyNot()
	if c.failed != nil {
		reason = ": setting it up on the daemon failed (" + c.failed.Error() + ")"
	}
	writeWrapped(w, "", "", head+reason+".")
	lead := "To make it work,"
	if keyKept {
		lead = "To use the certificate instead,"
	}
	writeFix(w, lead, "", "", c.fixLines())
}

// printCert says what config add did (or would do) about the certificate.
// usesCert: the entry written authenticates by certificate. keyKept: the
// known entry keeps the API key because the certificate could not be set up.
// troubleSaid: the verdict has said why the certificate does not work.
func printCert(w io.Writer, c *CertSetup, usesCert, keyKept, dryRun, troubleSaid bool) {
	if c == nil {
		return
	}
	would := func(did, will string) string {
		if dryRun {
			return will
		}
		return did
	}
	if c.pairNew {
		if dryRun {
			fmt.Fprintln(w)
			writeWrapped(w, "", "", "Would create your client certificate "+c.cert+".")
		} else {
			fmt.Fprintf(w, "\nCreated your client certificate %s\n(key %s, mode 0600). Its pin:\n   %s\n", c.cert, c.key, c.pin)
		}
	}

	// It does not work: why, and what would make it.
	if c.failed != nil || !c.usable() {
		if troubleSaid {
			return
		}
		head := "Your certificate does not work here"
		if keyKept {
			head = "The entry keeps the API key: your certificate does not work here"
		}
		fmt.Fprintln(w)
		c.writeTrouble(w, head, keyKept)
		return
	}
	if !usesCert {
		return
	}

	fmt.Fprintln(w)
	switch {
	case c.byDaemon:
		writeWrapped(w, "", "", "The daemon takes your certificate, as "+c.listedEnrollment()+".")
	case c.listedAs != "":
		writeWrapped(w, "", "", c.t.File+" lists your certificate as "+c.listedEnrollment()+".")
	default:
		name := c.enrolledAs
		if name == "" {
			name = c.name
		}
		if c.createFile {
			fmt.Fprintf(w, "%s %s,\nenrolling your certificate as %s (read-write).\n", would("Created", "Would create"), c.t.File, name)
		} else {
			fmt.Fprintf(w, "%s your certificate in %s\nas %s (read-write).\n", would("Enrolled", "Would enroll"), c.t.File, name)
		}
	}
	if c.state == certCanEnable && c.nameIt {
		// The line as it is written (addAccessFileLine), quoted if need be.
		fmt.Fprintf(w, "%s under apiserver: in %s:\n   access-file: %s\n",
			would("Added", "Would add"), c.t.DaemonConfig, yamlScalar(c.t.File))
		fmt.Fprintf(w, "\n%s an access file. This changes its TCP API:\n", would("The daemon now has", "The daemon would then have"))
		fmt.Fprintf(w, "   - the API key is read-write there, no longer admin\n")
		fmt.Fprintf(w, "   - TCP clients need TLS 1.3\n")
		fmt.Fprintf(w, "   - admin is the local admin socket's alone (root on its host)\n")
	}
	if c.state != certCanEnable {
		return
	}
	switch {
	case c.running && dryRun:
		writeWrapped(w, "", "", "Would reload the daemon over "+c.t.Socket+".")
	case c.running:
		// The daemon's reply, a sentence to a line.
		writeWrapped(w, "Reloaded: ", "  ", sentences(c.reloaded)...)
	default:
		fmt.Fprintf(w, "The daemon is not running: its next start %s.\n", would("reads the new files", "would read the files"))
		writeWrapped(w, "", "", "Nothing answers on "+c.t.Socket+".")
	}
	if dryRun && (c.addPin || c.createFile || c.nameIt) {
		writeWrapped(w, "", "", "(A dry run writes nothing, so whether config add may write these files is found out when it runs.)")
	}
}

// sentences splits s into its sentences, each with its full stop.
func sentences(s string) []string {
	parts := strings.Split(strings.TrimSpace(s), ". ")
	for i := range parts[:len(parts)-1] {
		parts[i] += "."
	}
	return parts
}
