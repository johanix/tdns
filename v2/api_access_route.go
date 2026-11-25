/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * /access: the daemon writes its own access file. tdns-ncli's client commands
 * call it over the local admin socket (it is admin, so the socket only).
 * Design: docs/2026-11-25-tdns-ncli-cert-setup-design.md section 3.
 */
package tdns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// AccessPost is an /access request.
type AccessPost struct {
	Command string // list | add | disable | enable | set-role | keyauth
	Name    string // the client (add, disable, enable, set-role)
	Pin     string // add
	Role    string // add, set-role: read-only or read-write
	Comment string // add
	KeyAuth string // keyauth: "on" or "off"
	DryRun  bool   // validate and render; write nothing
}

// AccessResponse is the answer to every /access request: what it did, and
// what is in force after it.
type AccessResponse struct {
	Msg        string
	Error      bool
	ErrorMsg   string
	File       string // the access file in force; "" when none
	KeyAuth    bool
	Clients    []ApiAccessStatusClient
	ServerPins []string // SPKI pins of the certificate the TCP API serves
	ConfigFile string   // the config file this daemon runs, absolute
	Rendered   string   `json:",omitempty"` // a dry run: the file it would write
}

// accessMu serializes the writers of the running access policy: /access, and
// the reloads that load the access file (reloadApiAccess).
var accessMu sync.Mutex

func APIaccess(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var ap AccessPost
		var resp AccessResponse
		if err := json.NewDecoder(r.Body).Decode(&ap); err != nil {
			resp = AccessResponse{Error: true, ErrorMsg: fmt.Sprintf("bad /access request: %v", err)}
		} else {
			resp = conf.runAccessCommand(ap)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// runAccessCommand runs one /access command. A write reads the file the
// running config names, applies the change, validates it with the daemon's
// own validator, writes it atomically (keeping .prev) and loads it as a
// reload would. A refused change writes nothing.
func (conf *Config) runAccessCommand(ap AccessPost) (resp AccessResponse) {
	// confMu: the running config's apiserver: block, which a reload replaces
	// (and then takes accessMu in reloadApiAccess: the same order).
	confMu.RLock()
	defer confMu.RUnlock()
	accessMu.Lock()
	defer accessMu.Unlock()
	defer conf.fillAccessInForce(&resp)
	refuse := func(format string, args ...any) AccessResponse {
		return AccessResponse{Error: true, ErrorMsg: fmt.Sprintf(format, args...)}
	}

	ap.Command = strings.ToLower(strings.TrimSpace(ap.Command))
	switch ap.Command {
	case "list", "add", "disable", "enable", "set-role", "keyauth":
	default:
		return refuse("unknown /access command %q", ap.Command)
	}
	path := conf.ApiServer.AccessFile
	if path == "" {
		advice := noAccessFileAdvice(conf.Internal.CfgFile)
		if ap.Command == "list" {
			return AccessResponse{Msg: "No access file: the API key is admin on the TCP API.\n\n" + advice}
		}
		return refuse("%s", advice)
	}
	if ap.Command == "list" {
		return AccessResponse{Msg: conf.accessInForceLine()}
	}

	create := ap.Command == "add" || ap.Command == "keyauth"
	af, old, err := readAccessFileForEdit(path, create)
	if err != nil {
		return refuse("%v", err)
	}
	msg, changed, err := applyAccessChange(af, ap)
	if err != nil {
		return refuse("%v", err)
	}
	done := path + " written"
	// A missing file (old nil) is written even when the policy it would
	// hold is the empty one (keyauth on, no clients): a file the config
	// names but that is not there cannot be loaded.
	if changed || old == nil {
		if err := ValidateAccessFile(af); err != nil {
			return refuse("not writing %s: %v", path, err)
		}
		out, err := renderAccessFile(af, absConfigFile(conf.Internal.CfgFile))
		if err != nil {
			return refuse("%v", err)
		}
		if ap.DryRun {
			return AccessResponse{Msg: msg + "\nDry run: would write " + path + ":", Rendered: string(out)}
		}
		if err := writeAccessFile(path, old, out); err != nil {
			return refuse("not written: %v", err)
		}
	} else if ap.DryRun {
		return AccessResponse{Msg: msg}
	} else {
		// Loaded all the same: a hand edit not yet reloaded, or a write
		// whose load failed, is then in force when this answers success.
		done = path + " needs no change"
	}
	if conf.Internal.ApiAccess == nil {
		return refuse("%s, but NOT loaded: this daemon has no management API policy to load it into", done)
	}
	_, stopped, err := conf.loadAccessPolicy(path)
	if err != nil {
		return refuse("%s, but NOT loaded (the running policy is unchanged): %v", done, err)
	}
	msg += "\n" + conf.accessInForceLine()
	if len(stopped) > 0 {
		msg += fmt.Sprintf("\nTCP API STOPPED on %s: it was plaintext, and the access\nfile requires TLS. Restart the daemon with usetls: true.",
			strings.Join(stopped, ", "))
	}
	return AccessResponse{Msg: msg}
}

// fillAccessInForce puts what is in force in resp: the running policy, the
// served certificate's pins and the config file.
func (conf *Config) fillAccessInForce(resp *AccessResponse) {
	resp.KeyAuth = true // no access file: the key works, as admin
	if st := conf.apiAccessStatus(); st != nil {
		resp.File, resp.KeyAuth, resp.Clients = st.File, st.KeyAuth, st.Clients
	}
	resp.ServerPins = apiServedPins()
	if cfg := conf.Internal.CfgFile; cfg != "" {
		resp.ConfigFile = absConfigFile(cfg)
	}
}

// accessInForceLine says in one line what policy runs.
func (conf *Config) accessInForceLine() string {
	st := conf.apiAccessStatus()
	switch {
	case st == nil:
		return "In force: no access file."
	case st.Error != "":
		return "In force: none. The access file could not be used at start-up,\nso the TCP API answers 503: " + st.Error
	}
	return fmt.Sprintf("In force: %d client(s), keyauth %s.", len(st.Clients), onOff(st.KeyAuth))
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// applyAccessChange applies ap to af. changed is false when af already is
// as asked: nothing to write, and msg says so.
func applyAccessChange(af *AccessFile, ap AccessPost) (msg string, changed bool, err error) {
	find := func() (*AccessClient, error) {
		for i := range af.Clients {
			if af.Clients[i].Name == ap.Name {
				return &af.Clients[i], nil
			}
		}
		return nil, fmt.Errorf("no client %q", ap.Name)
	}
	switch ap.Command {
	case "add":
		switch {
		case ap.Name == "":
			return "", false, errors.New("a client needs a name")
		case strings.ContainsAny(ap.Name, " \t"):
			return "", false, errors.New("a client name has no spaces")
		}
		if c, err := find(); err == nil {
			switch {
			case c.Pin != ap.Pin:
				return "", false, fmt.Errorf("%q is already there with another pin:\ndisable it first, or use another name", ap.Name)
			case c.Role != ap.Role:
				return "", false, fmt.Errorf("%q is already there as %s; change its role\nwith set-role", ap.Name, c.Role)
			case c.Disabled:
				return fmt.Sprintf("%s is already there (%s), but disabled:\nenable it to let it in.", ap.Name, c.Role), false, nil
			}
			return fmt.Sprintf("%s is already there (%s).", ap.Name, c.Role), false, nil
		}
		af.Clients = append(af.Clients, AccessClient{Name: ap.Name, Pin: ap.Pin, Role: ap.Role, Comment: ap.Comment})
		return fmt.Sprintf("Added %s (%s).", ap.Name, ap.Role), true, nil
	case "disable", "enable":
		c, err := find()
		if err != nil {
			return "", false, err
		}
		if want := ap.Command == "disable"; c.Disabled != want {
			c.Disabled = want
			return fmt.Sprintf("%s: %sd.", ap.Name, ap.Command), true, nil
		}
		return fmt.Sprintf("%s is already %sd.", ap.Name, ap.Command), false, nil
	case "set-role":
		c, err := find()
		if err != nil {
			return "", false, err
		}
		if c.Role == ap.Role {
			return fmt.Sprintf("%s is already %s.", ap.Name, ap.Role), false, nil
		}
		c.Role = ap.Role
		return fmt.Sprintf("%s is now %s.", ap.Name, ap.Role), true, nil
	case "keyauth":
		var on bool
		switch ap.KeyAuth {
		case "on":
			on = true
		case "off":
		default:
			return "", false, fmt.Errorf("keyauth on or off, not %q", ap.KeyAuth)
		}
		if af.KeyAuthOn() == on {
			return "keyauth is already " + ap.KeyAuth + ".", false, nil
		}
		af.KeyAuth = &on
		if on {
			return "keyauth on: the API key works on the TCP API (read-write).", true, nil
		}
		msg := "keyauth off: the TCP API needs a client certificate now.\nThe local socket is unaffected."
		enabled := 0
		for _, c := range af.Clients {
			if !c.Disabled {
				enabled++
			}
		}
		if enabled == 0 {
			msg += "\nNo client is enabled: the TCP API is closed to all but the socket."
		}
		return msg, true, nil
	}
	return "", false, fmt.Errorf("unknown /access command %q", ap.Command)
}

// readAccessFileForEdit reads and parses the access file at path, returning
// its bytes too (nil when it does not exist). A missing file is an empty
// policy when create is set, and an error otherwise.
func readAccessFileForEdit(path string, create bool) (*AccessFile, []byte, error) {
	old, err := os.ReadFile(path)
	switch {
	case err == nil:
		af, perr := ParseAccessFile(old)
		if perr != nil {
			return nil, nil, fmt.Errorf("%s does not parse (%v); fix it by hand first", path, perr)
		}
		return af, old, nil
	case errors.Is(err, fs.ErrNotExist):
		if derr := danglingSymlink(path); derr != nil {
			return nil, nil, derr
		}
		if create {
			return &AccessFile{}, nil, nil
		}
		return nil, nil, fmt.Errorf("%s does not exist yet; client add creates it", path)
	}
	return nil, nil, err
}

// danglingSymlink refuses path when it is a symlink whose target does not
// resolve: a write would replace the link with a file, not create its
// target. nil for anything else, a missing path among them.
func danglingSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		return nil
	}
	if _, err := filepath.EvalSymlinks(path); err != nil {
		dest, _ := os.Readlink(path)
		return fmt.Errorf("%s is a symlink to %s, which does not resolve;\nnot replacing the link: create its target, or remove the link", path, dest)
	}
	return nil
}

// renderAccessFile is the file as the daemon writes it: a header, keyauth
// spelled out, and the clients. Comments a person adds are not kept; notes go
// in a client's comment:.
func renderAccessFile(af *AccessFile, daemonConfig string) ([]byte, error) {
	keyauth := af.KeyAuthOn()
	out := AccessFile{KeyAuth: &keyauth, Clients: af.Clients}
	if out.Clients == nil {
		out.Clients = []AccessClient{}
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Access file of the management API of %s.\n", daemonConfig)
	fmt.Fprintf(&buf, "# Written by the daemon (tdns-ncli <daemon> client ...). Hand edits\n")
	fmt.Fprintf(&buf, "# work, but comments are not kept: put notes in a client's comment:.\n")
	fmt.Fprintf(&buf, "# Roles: read-only, read-write (admin is the local socket's alone).\n")
	fmt.Fprintf(&buf, "# keyauth: false turns the API key off.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(3)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	enc.Close()
	return buf.Bytes(), nil
}

// writeAccessFile replaces the access file at path (following a symlink)
// with data, after saving old, its previous content, as path.prev; both
// atomically. The file keeps its mode, owner and group; a new one (old nil)
// is 0600 and the daemon's own.
func writeAccessFile(path string, old, data []byte) error {
	target := path
	if real, err := filepath.EvalSymlinks(path); err == nil {
		target = real
	} else if derr := danglingSymlink(path); derr != nil {
		return derr
	}
	var like os.FileInfo
	if old != nil {
		fi, err := os.Stat(target)
		if err != nil {
			return err
		}
		like = fi
		// First: a failed write leaves the previous .prev, the operator's
		// way back, as it was, and the live file is not touched without it.
		if err := replaceFileLike(path+".prev", old, fi); err != nil {
			return fmt.Errorf("saving %s.prev: %w", path, err)
		}
	}
	return replaceFileLike(target, data, like)
}

// replaceFileLike replaces path with data: a temporary file in the same
// directory, synced and renamed over it. It gets like's mode, owner and
// group, so a file root writes for a daemon user stays that user's; with
// like nil it is 0600.
func replaceFileLike(path string, data []byte, like os.FileInfo) error {
	mode := os.FileMode(0o600)
	if like != nil {
		mode = like.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil && like != nil {
		err = chownLike(tmp, like)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// chownLike gives f like's owner and group when they differ from f's.
// Nothing to do where the platform has no owners (fileOwner).
func chownLike(f *os.File, like os.FileInfo) error {
	uid, gid, ok := fileOwner(like)
	if !ok {
		return nil
	}
	if fi, err := f.Stat(); err == nil {
		if u, g, ok := fileOwner(fi); ok && u == uid && g == gid {
			return nil
		}
	}
	return f.Chown(uid, gid)
}

// noAccessFileAdvice is the answer to /access on a daemon whose config names
// no access file (design section 4, Q2): the line to add, what it changes,
// and the reload that makes the daemon read it. Lines of at most 72.
func noAccessFileAdvice(cfg string) string {
	suggested := "<config dir>/<config name>-access.yaml"
	if cfg != "" {
		cfg = absConfigFile(cfg)
		base := strings.TrimSuffix(filepath.Base(cfg), filepath.Ext(cfg))
		suggested = filepath.Join(filepath.Dir(cfg), base+"-access.yaml")
	} else {
		cfg = "<config>"
	}
	role := AppTypeToString[Globals.App.Type]
	if role == "" {
		role = "<daemon>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "No access file: the daemon config names none:\n   %s\n", cfg)
	fmt.Fprintf(&b, "To turn one on, add under apiserver: in that file:\n\n")
	fmt.Fprintf(&b, "   access-file: %s\n\n", suggested)
	fmt.Fprintf(&b, "That changes three things on the TCP API:\n")
	fmt.Fprintf(&b, " - the API key drops from admin to read-write;\n")
	fmt.Fprintf(&b, " - TLS is required (with usetls: false the TCP listeners\n")
	fmt.Fprintf(&b, "   stay off);\n")
	fmt.Fprintf(&b, " - it takes TLS 1.3 only.\n")
	fmt.Fprintf(&b, "Then make the daemon read it (no restart needed):\n\n")
	fmt.Fprintf(&b, "   tdns-ncli %s config reload \\\n      --daemon-config %s\n\n", role, cfg)
	fmt.Fprintf(&b, "and run this command again.")
	return b.String()
}
