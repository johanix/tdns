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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

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
	accessOld  []byte // the access file as read; nil when it does not exist
	keyAuthOff bool   // the access file says keyauth: false
	listedAs   string // the access file already lists the pin, as this name
	noTLS      bool   // the daemon's TCP API has no TLS
	noSocket   bool   // the daemon serves no local admin socket

	// What making it work takes.
	addPin, createFile, nameIt bool
	daemonOld, daemonNew       []byte // the daemon config, and with access-file: added
	running                    bool   // the daemon on the socket runs this config

	state certState
	why   string // why it cannot work (certCannot)

	// What apply did.
	enrolledAs string // the name the pin was added under
	reloaded   string // the daemon's reply to the reload
	failed     error  // apply failed, and put everything back
}

// usable says whether the certificate works, or config add can make it work.
func (c *CertSetup) usable() bool {
	return c.state == certWorks || c.state == certCanEnable
}

// changesDaemon says whether making the certificate work changes the daemon's
// files.
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
// here when there is none (not in a dry run), as `client init` does.
//
// word is the command word the advice it prints uses for the daemon.
func planCert(o AddOptions, info *DaemonApi, word string) *CertSetup {
	c := &CertSetup{info: info, role: info.Role, word: word, t: accessTargetOf(info)}

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
	c.cert, c.key = clientCertPaths(ReadCliClientConf(o.CliConfig))
	c.name = defaultClientName()
	if _, err := os.Stat(c.cert); err != nil && o.DryRun {
		c.pairNew = true
	} else {
		pin, created, err := ensureClientCert(c.cert, c.key, defaultClientName())
		if err != nil {
			return c.cannot(fmt.Sprintf("your client certificate: %v", err))
		}
		c.pin, c.pairNew, c.name = pin, created, clientNameOf(c.cert)
	}

	if c.t.Configured && !filepath.IsAbs(c.t.File) {
		return c.cannot(fmt.Sprintf("apiserver.access-file %q is not an absolute path, which the daemon refuses", c.t.File))
	}
	af, old, err := readAccessFile(c.t, true)
	if err != nil {
		return c.cannot(err.Error())
	}
	c.accessOld, c.keyAuthOff = old, !af.KeyAuthOn()
	if cl := clientByPin(af, c.pin); c.pin != "" && cl != nil {
		c.listedAs = cl.Name
		if cl.Disabled {
			c.state = certDisabled
			return c
		}
	}
	c.addPin, c.createFile, c.nameIt = c.listedAs == "", old == nil, !c.t.Configured
	if !c.addPin && !c.createFile && !c.nameIt {
		c.state = certWorks
		return c
	}

	// It takes changes on the daemon's side. Can they be made from here?
	if err := canReplace(c.t.File); err != nil {
		return c.cannot(fmt.Sprintf("config add cannot write %s here (%v)", c.t.File, err))
	}
	if c.nameIt {
		cur, err := os.ReadFile(info.ConfigFile)
		if err != nil {
			return c.cannot(err.Error())
		}
		next, err := addAccessFileLine(cur, c.t.File)
		if err != nil {
			return c.cannot(fmt.Sprintf("config add cannot add access-file: to %s (%v)", info.ConfigFile, err))
		}
		if err := canReplace(info.ConfigFile); err != nil {
			return c.cannot(fmt.Sprintf("config add cannot write %s here (%v)", info.ConfigFile, err))
		}
		c.daemonOld, c.daemonNew = cur, next
	}
	running, err := socketDaemon(c.role, c.t)
	if err != nil {
		return c.cannot(err.Error())
	}
	c.running, c.state = running, certCanEnable
	return c
}

// apply makes the daemon accept the certificate: the pin added to the access
// file (created if need be), the file named in the daemon config if it was
// not, and the daemon reloaded over its local socket when it runs, the
// running policy then checked for the pin. Each step as `client add` takes it
// (the access file's lock, the daemon's own validator, the write with .prev,
// the check of whose daemon answers). A step that fails puts back what the
// steps before it changed; c.failed is set to why.
func (c *CertSetup) apply(ctx context.Context) error {
	err := c.applySteps(ctx)
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
		c.listedAs = cl.Name
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

	var undo []func() error
	putBack := func(cause error) error {
		var failed []string
		for i := len(undo) - 1; i >= 0; i-- {
			if uerr := undo[i](); uerr != nil {
				failed = append(failed, uerr.Error())
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("%v; putting the files back FAILED (%s): check %s and %s by hand",
				cause, strings.Join(failed, "; "), c.t.File, c.t.DaemonConfig)
		}
		return fmt.Errorf("%v; the files are as they were", cause)
	}

	if accessNew != nil {
		if err := writeAccessFile(c.t.File, old, accessNew, c.t.DaemonConfig); err != nil {
			return err
		}
		undo = append(undo, func() error {
			if old == nil {
				return os.Remove(c.t.File)
			}
			return writeFileAtomicLike(c.t.File, old, nil)
		})
	}

	if c.nameIt {
		cur, err := os.ReadFile(c.t.DaemonConfig)
		if err != nil {
			return putBack(err)
		}
		next := c.daemonNew
		if !bytes.Equal(cur, c.daemonOld) {
			if next, err = addAccessFileLine(cur, c.t.File); err != nil {
				return putBack(fmt.Errorf("cannot add access-file: to %s (%v)", c.t.DaemonConfig, err))
			}
		}
		if err := writeFileAtomicLike(c.t.DaemonConfig, next, nil); err != nil {
			return putBack(err)
		}
		undo = append(undo, func() error { return writeFileAtomicLike(c.t.DaemonConfig, cur, nil) })
		// Read back the way config add read it: the daemon must now name
		// this access file, and say everything else as it did.
		after, err := ReadDaemonApi(c.t.DaemonConfig, c.role)
		if err != nil || !sameApiApartFromAccess(c.info, after) || after.AccessFile != c.t.File {
			return putBack(fmt.Errorf("%s does not read back as before plus access-file: %s (does an include: file set apiserver:?)", c.t.DaemonConfig, c.t.File))
		}
	}

	if !c.running {
		return nil // the next start reads the files
	}
	msg, err := reloadAccess(c.role, c.t)
	if err != nil {
		return putBack(err)
	}
	if err := c.inForce(); err != nil {
		return putBack(err)
	}
	c.reloaded = msg
	return nil
}

// sameApiApartFromAccess says whether a and b, two reads of one daemon
// config, say the same about its API, the access file aside.
func sameApiApartFromAccess(a, b *DaemonApi) bool {
	return a.ConfigFile == b.ConfigFile && reflect.DeepEqual(a.Addresses, b.Addresses) &&
		a.ApiKey == b.ApiKey && a.Socket == b.Socket && a.CertFile == b.CertFile && a.UseTLS == b.UseTLS
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
	}
	for _, cl := range a.Clients {
		if cl.Pin == c.pin && !cl.Disabled {
			return nil
		}
	}
	return errors.New("reloaded, but the policy the daemon runs does not have your certificate")
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
			"   tdns-ncli " + c.word + " client enable " + c.listedAs,
			"then run config add again.",
		}
	}
	lines := []string{
		"on the daemon's host, as root:",
		fmt.Sprintf("   tdns-ncli %s client add %s --pin %s --role read-write", c.word, c.name, c.pinOrHint()),
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

// printRefusal prints r as a refusal, the way dieOn does.
func printRefusal(w io.Writer, r addRefusal) {
	fmt.Fprintf(w, "Error: %s.\n", r.why)
	for _, n := range r.notes {
		fmt.Fprintf(w, "  %s\n", n)
	}
	for i, l := range r.fix {
		lead := "       "
		if i == 0 {
			lead = "  Fix: "
		}
		fmt.Fprintf(w, "%s%s\n", lead, l)
	}
}

// printCert says what config add did (or would do) about the certificate.
// usesCert: the entry written authenticates by certificate. keyKept: the
// known entry keeps the API key because the certificate could not be set up.
func printCert(w io.Writer, c *CertSetup, usesCert, keyKept, dryRun bool) {
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
			fmt.Fprintf(w, "\nWould create your client certificate %s.\n", c.cert)
		} else {
			fmt.Fprintf(w, "\nCreated your client certificate %s\n(key %s, mode 0600). Its pin:\n   %s\n", c.cert, c.key, c.pin)
		}
	}

	// It does not work: why, and what would make it.
	if c.failed != nil || !c.usable() {
		if keyKept {
			fmt.Fprintf(w, "\nThe entry keeps the API key. Your certificate does not work here:\n%s.\nTo use the certificate instead,\n", c.whyNot())
		} else {
			fmt.Fprintf(w, "\nYour certificate does not work here:\n%s.\nTo make it work,\n", c.whyNot())
		}
		for _, l := range c.fixLines() {
			fmt.Fprintf(w, "%s\n", l)
		}
		return
	}
	if !usesCert {
		return
	}

	switch {
	case c.listedAs != "":
		fmt.Fprintf(w, "\n%s lists your certificate as %s.\n", c.t.File, c.listedAs)
	default:
		name := c.enrolledAs
		if name == "" {
			name = c.name
		}
		verb := would("Enrolled", "Would enroll")
		if c.createFile {
			verb = would("Created "+c.t.File+",\nenrolling", "Would create "+c.t.File+",\nenrolling")
			fmt.Fprintf(w, "\n%s your certificate as %s (read-write).\n", verb, name)
		} else {
			fmt.Fprintf(w, "\n%s your certificate in %s\nas %s (read-write).\n", verb, c.t.File, name)
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
	if c.state != certCanEnable || dryRun {
		if dryRun && c.state == certCanEnable {
			if c.running {
				fmt.Fprintf(w, "Would reload the daemon over %s.\n", c.t.Socket)
			} else {
				fmt.Fprintf(w, "The daemon is not running (nothing on %s);\nits next start would read the files.\n", c.t.Socket)
			}
		}
		return
	}
	if c.running {
		fmt.Fprintf(w, "Reloaded: %s\n", c.reloaded)
	} else {
		fmt.Fprintf(w, "The daemon is not running (nothing on %s);\nits next start reads the new files.\n", c.t.Socket)
	}
}
