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
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
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

	// What apply did.
	enrolledAs string     // the name the pin was added under
	reloaded   string     // the daemon's reply to the reload
	failed     error      // apply failed, and put everything back
	undo       []fileUndo // how to put back the files apply wrote
	didReload  bool       // apply reloaded the daemon
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
// reads.
//
// word is the command word the advice it prints uses for the daemon.
func planCert(o AddOptions, info *DaemonApi, word string) *CertSetup {
	c := &CertSetup{info: info, role: info.Role, word: word, t: accessTargetOf(info), dryRun: o.DryRun}

	relative := c.t.Configured && !filepath.IsAbs(c.t.File)
	var af *tdns.AccessFile
	var old []byte
	var aerr error
	if !relative {
		af, old, aerr = readAccessFile(c.t, true)
	}
	view, status, serr := c.askSocket()
	if view == sockOther {
		// A socket that answers for another daemon, or with an error, is a
		// daemon that is not identified: neither it nor the file is taken.
		why := serr.Error()
		if strings.HasPrefix(why, "cannot ") {
			why = "config add " + why // read after "because"
		}
		c.keyUnknown = why
		return c.cannot(why)
	}

	// The key.
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
		r := c.ping(info, tdns.ClientOptions{AuthMethod: "X-API-Key", ApiKey: info.ApiKey})
		switch {
		case r.taken:
		case r.status == http.StatusServiceUnavailable:
			c.keyOff, c.keyWhy = true, "its TCP API is closed, as it cannot use its access file"
		case r.answered:
			c.keyOff, c.keyWhy = true, "asked over TCP, it refuses the key"
		case r.down:
			view = sockAbsent // nothing on its socket we may open, nothing on TCP: not running
		default:
			c.keyUnknown = c.unasked(serr, r)
		}
	}
	if view == sockAbsent {
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
	// ensureClientCert would make it (it never overwrites a key).
	c.cert, c.key = clientCertPaths(ReadCliClientConf(o.CliConfig))
	c.name = defaultClientName()
	_, cerr := os.Stat(c.cert)
	switch {
	case o.DryRun && cerr != nil && !errors.Is(cerr, fs.ErrNotExist):
		return c.cannot(fmt.Sprintf("your client certificate cannot be used (%v)", cerr))
	case o.DryRun && cerr != nil:
		_, kerr := os.Stat(c.key)
		switch {
		case kerr == nil:
			return c.cannot(fmt.Sprintf("your client certificate cannot be used (%s exists without its certificate %s)", c.key, c.cert))
		case !errors.Is(kerr, fs.ErrNotExist):
			return c.cannot(fmt.Sprintf("your client certificate cannot be used (%v)", kerr))
		}
		c.pairNew = true
	default:
		pin, created, err := ensureClientCert(c.cert, c.key, defaultClientName())
		if err != nil {
			return c.cannot(fmt.Sprintf("your client certificate cannot be used (%v)", err))
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
		case r.answered:
			// It runs, and does not take it. Nothing can be changed from
			// here (its socket is not ours to use): what the file says
			// only shapes the advice.
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
	sockAbsent  sockView = iota // nothing listens there: not running
	sockRunning                 // it answered, and runs this config
	sockShut                    // not ours to use (not root), or there is none: asked over TCP
	sockOther                   // another daemon, or one that refused: not identified
)

// askSocket asks the daemon on its local admin socket which config it runs,
// and the policy in force.
func (c *CertSetup) askSocket() (sockView, tdns.ConfigResponse, error) {
	if c.t.Socket == "" {
		return sockShut, tdns.ConfigResponse{}, errors.New("it serves no local admin socket")
	}
	resp, err := SendConfigCommand(tdns.NewClient(c.role, "unix://"+c.t.Socket, "", "none", ""), tdns.ConfigPost{Command: "status"})
	switch {
	case err == nil:
		if rerr := runsConfig(resp, c.t); rerr != nil {
			return sockOther, resp, rerr
		}
		return sockRunning, resp, nil
	case nothingListening(err):
		return sockAbsent, resp, nil
	case errors.Is(err, os.ErrPermission):
		return sockShut, resp, fmt.Errorf("its local admin socket %s is not ours to open", c.t.Socket)
	}
	return sockOther, resp, fmt.Errorf("cannot ask the daemon on %s which config it runs (%v)", c.t.Socket, err)
}

// ping pings the daemon's TCP API with o's credentials, the daemon verified
// by the pin of its certificate (daemonTCP).
func (c *CertSetup) ping(info *DaemonApi, o tdns.ClientOptions) pingReply {
	base, pin, err := daemonTCP(info)
	if err != nil {
		return pingReply{err: err}
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

// pingAs pings the TCP API at base, the daemon verified by pin, with the
// credentials in o: the client certificate, or the API key.
func pingAs(base, pin string, o tdns.ClientOptions) pingReply {
	o.Pins = []string{pin}
	api := tdns.NewClientWithOptions("config add", base, o)
	api.Client.Timeout = 5 * time.Second
	body, err := json.Marshal(tdns.PingPost{Msg: "config add", Pings: 1})
	if err != nil {
		return pingReply{}
	}
	status, buf, err := api.Post("/ping", body)
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

// apply makes the daemon accept the certificate: the pin added to the access
// file (created if need be), the file named in the daemon config if it was
// not, and the daemon reloaded over its local socket when it runs, the
// running policy then checked for the pin. Each step as `client add` takes it
// (the access file's lock, the daemon's own validator, the write with .prev,
// the check of whose daemon answers); the daemon config is written the way
// the access file is, its old bytes kept as .prev and the new file renamed
// over it with its owner, group and mode. A step that fails puts back what
// the steps before it changed (rollback; the .prev files stay); c.failed is
// set to why. After a success, rollback stays possible until the caller has
// written the CLI config.
func (c *CertSetup) apply(ctx context.Context) error {
	err := c.applySteps(ctx)
	if err != nil {
		err = fmt.Errorf("%v; %s", err, c.rollback())
	}
	c.failed = err
	return err
}

func (c *CertSetup) applySteps(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	unlock, err := lockCliConfig(ctx, c.t.File)
	if err != nil {
		return err
	}
	defer unlock()

	// The daemon config must still name what it named when config add read
	// it: an operator may have pointed it at another access file since, and
	// enrolling the pin in this one would then do nothing.
	now, err := ReadDaemonApi(c.t.DaemonConfig, c.role)
	if err != nil {
		return err
	}
	if planned := map[bool]string{true: c.t.File, false: ""}[c.t.Configured]; now.AccessFile != planned {
		return fmt.Errorf("%s now names access-file %q, not %q as when config add read it; run config add again", c.t.DaemonConfig, now.AccessFile, planned)
	}

	// Again under the lock: a `client` edit may have changed it since.
	af, old, err := readAccessFile(c.t, true)
	if err != nil {
		return err
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
		// As the access file is written (writeAccessFile): the old bytes
		// kept as .prev first, then the new file renamed over the config,
		// with its owner, group and mode. A rollback puts the old bytes
		// back the same way, and leaves the .prev.
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
	c.didReload = true
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

// rollback puts back what apply changed, and says how that went: each file
// as it was before (removed, if apply created it), unless it has changed
// since apply wrote it, which is then left as it is; and, when apply
// reloaded the daemon, a reload over its socket so that it runs the files as
// they are again, checked by asking it what it runs. The .prev files stay.
// Done at most once.
func (c *CertSetup) rollback() string {
	if len(c.undo) == 0 && !c.didReload {
		return "nothing on the daemon's side was changed"
	}
	var left, failed []string
	for i := len(c.undo) - 1; i >= 0; i-- {
		u := c.undo[i]
		cur, err := os.ReadFile(u.path)
		switch {
		case err != nil && !(u.old == nil && errors.Is(err, fs.ErrNotExist)):
			failed = append(failed, err.Error())
		case err == nil && !bytes.Equal(cur, u.wrote):
			left = append(left, u.path)
		case err == nil && u.old == nil:
			if rerr := os.Remove(u.path); rerr != nil {
				failed = append(failed, rerr.Error())
			}
		case err == nil:
			if werr := writeFileAtomicLike(u.path, u.old, nil); werr != nil {
				failed = append(failed, werr.Error())
			}
		}
	}
	c.undo = nil
	var sb strings.Builder
	switch {
	case len(failed) > 0:
		fmt.Fprintf(&sb, "putting the files back FAILED (%s): check %s and %s by hand", strings.Join(failed, "; "), c.t.File, c.t.DaemonConfig)
	case len(left) > 0:
		fmt.Fprintf(&sb, "the files are put back, except %s, changed since config add wrote it, and left as it is", strings.Join(left, " and "))
	default:
		sb.WriteString("the files are as they were")
	}
	if !c.didReload {
		return sb.String()
	}
	c.didReload = false
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
		return fmt.Errorf("reloaded, but asking the daemon what it runs failed: %v", err)
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

// pinOrHint is the pin, or what stands for it before the pair exists.
func (c *CertSetup) pinOrHint() string {
	if c.pin == "" {
		return "<your pin>"
	}
	return c.pin
}

// fixLines say what makes the certificate work when config add could not.
func (c *CertSetup) fixLines() []string {
	switch {
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
	}
	if c.listedAs != "" {
		// The pin is there already: what is left is the daemon reading it.
		if !c.t.Configured {
			return []string{
				"on the daemon's host, as root, add under apiserver: in " + c.t.DaemonConfig + ":",
				"   access-file: " + c.t.File,
				"and reload the daemon; then run config add again.",
			}
		}
		return []string{
			"on the daemon's host, as root:",
			"   tdns-ncli " + c.word + " config reload",
			"then run config add again.",
		}
	}
	lines := []string{
		"on the daemon's host, as root:",
		fmt.Sprintf("   tdns-ncli %s client add %s --pin %s --role read-write", c.word, shellQuote(c.name), c.pinOrHint()),
	}
	if !c.t.Configured {
		lines = append(lines,
			"and add under apiserver: in "+c.t.DaemonConfig+":",
			"   access-file: "+c.t.File,
			"and reload the daemon; then run config add again.")
	} else {
		lines = append(lines, "then run config add again.")
	}
	return lines
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
		fmt.Fprintf(w, "%s under apiserver: in %s:\n   access-file: %s\n",
			would("Added", "Would add"), c.t.DaemonConfig, c.t.File)
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
