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
	Command string // list | add | disable | enable | set-role
	Name    string // the client (add, disable, enable, set-role)
	Pin     string // add
	Role    string // add, set-role: read-only or read-write
	Comment string // add
	DryRun  bool   // validate and render; write nothing
}

// AccessResponse is the answer to every /access request: what it did, and
// what is in force after it.
type AccessResponse struct {
	Msg      string
	Error    bool
	ErrorMsg string
	// File is the daemon's access file, there or not (Missing).
	File string
	// Missing: there is no access file, so the daemon takes no remote
	// clients. The operator creates it (touch); the daemon never does.
	Missing    bool `json:",omitempty"`
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

// runAccessCommand runs one /access command. Every command first loads the
// access file into force, so a file created or edited by hand since the
// last load counts, with no reload. A write then applies the change,
// validates it with the daemon's own validator, writes it atomically
// (keeping .prev) and loads it. The daemon never creates the file: with no
// file every write is refused, saying how to create it. A refused change
// writes nothing.
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
	case "list", "add", "disable", "enable", "set-role":
	case "keyauth":
		return refuse("keyauth is gone: there is no API key any more, and the\nTCP API takes client certificates only")
	default:
		return refuse("unknown /access command %q", ap.Command)
	}
	path := conf.ApiServer.AccessFile
	switch {
	case path == "":
		return refuse("this daemon runs no config file, so it has no access file")
	case conf.Internal.ApiAccess == nil:
		return refuse("this daemon has no management API policy to load an access file into")
	}
	_, lerr := conf.loadAccessPolicy(path)
	missing := errors.Is(lerr, fs.ErrNotExist)
	switch {
	case ap.Command == "list" && (missing || lerr == nil):
		return AccessResponse{Msg: conf.accessInForceLine()}
	case ap.Command == "list":
		return AccessResponse{Msg: fmt.Sprintf("%s\nThe access file does not load (the policy above is unchanged):\n   %v", conf.accessInForceLine(), lerr)}
	case missing:
		if derr := danglingSymlink(path); derr != nil {
			return refuse("%v", derr)
		}
		return refuse("%s", accessFileMissing(path))
	}

	af, old, err := readAccessFileForEdit(path)
	if err != nil {
		return refuse("%v", err)
	}
	msg, changed, err := applyAccessChange(af, ap)
	if err != nil {
		return refuse("%v", err)
	}
	done := path + " written"
	// A file that still has the obsolete keyauth: line is written even with
	// no other change, so the line goes.
	if changed || af.KeyAuth != nil {
		af.KeyAuth = nil
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
		done = path + " needs no change"
	}
	if _, err := conf.loadAccessPolicy(path); err != nil {
		return refuse("%s, but NOT loaded (the running policy is unchanged): %v", done, err)
	}
	return AccessResponse{Msg: msg + "\n" + conf.accessInForceLine()}
}

// fillAccessInForce puts what is in force in resp: the access file and the
// running policy, the served certificate's pins and the config file.
func (conf *Config) fillAccessInForce(resp *AccessResponse) {
	resp.File = conf.ApiServer.AccessFile
	if st := conf.apiAccessStatus(); st != nil {
		resp.Missing, resp.Clients = st.Missing, st.Clients
	}
	resp.ServerPins = apiServedPins()
	if cfg := conf.Internal.CfgFile; cfg != "" {
		resp.ConfigFile = absConfigFile(cfg)
	}
}

// accessInForceLine says what policy runs, verdict first.
func (conf *Config) accessInForceLine() string {
	st := conf.apiAccessStatus()
	switch {
	case st == nil:
		return "In force: nothing (no management API policy)."
	case st.Missing:
		return fmt.Sprintf("No access file, so no remote clients. To take them:\n   touch %s", st.File)
	case st.Error != "":
		return "In force: none. The access file does not load, so the TCP\nAPI answers 503: " + st.Error
	}
	return fmt.Sprintf("In force: %d client(s).", len(st.Clients))
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
				// Disabled or not, the name is taken, and no command
				// changes a client's pin.
				return "", false, fmt.Errorf("%q is already there with another pin:\nuse another name", ap.Name)
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
	}
	return "", false, fmt.Errorf("unknown /access command %q", ap.Command)
}

// readAccessFileForEdit reads and parses the access file at path, returning
// its bytes too. The file must be there (the daemon never creates it), and
// it must pass CheckAccessFileMode: a write keeps the file's mode.
func readAccessFileForEdit(path string) (*AccessFile, []byte, error) {
	old, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if err := CheckAccessFileMode(path); err != nil {
		return nil, nil, err
	}
	af, perr := ParseAccessFile(old)
	if perr != nil {
		return nil, nil, fmt.Errorf("%s does not parse (%v); fix it by hand first", path, perr)
	}
	return af, old, nil
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

// renderAccessFile is the file as the daemon writes it: a header and the
// clients. Comments a person adds are not kept; notes go in a client's
// comment:.
func renderAccessFile(af *AccessFile, daemonConfig string) ([]byte, error) {
	out := AccessFile{Clients: af.Clients}
	if out.Clients == nil {
		out.Clients = []AccessClient{}
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Access file of the management API of %s.\n", daemonConfig)
	fmt.Fprintf(&buf, "# Written by the daemon (tdns-ncli <daemon> client ...). Hand edits\n")
	fmt.Fprintf(&buf, "# work, but comments are not kept: put notes in a client's comment:.\n")
	fmt.Fprintf(&buf, "# Roles: read-only, read-write (admin is the local socket's alone).\n")
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
// atomically. The file keeps its mode, owner and group; with old nil (no
// file before; /access never asks for that) it would be 0600 and the
// daemon's own.
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
