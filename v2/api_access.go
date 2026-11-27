/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The access file of the network management API: who may connect over TCP,
 * by certificate pin, with which role. Designs:
 * docs/2026-11-20-api-pinning-mtls-roles-design.md sections 3.3 and 4, and
 * docs/2026-11-26-tdns-ncli-simple-setup-design.md (always on, no API key).
 */
package tdns

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ApiRole is what a caller of the management API may do. The roles are a
// ladder: each may do everything the one below it may.
type ApiRole int

const (
	RoleNone      ApiRole = iota // not authenticated
	RoleReadOnly                 // reports only; no key material
	RoleReadWrite                // operates; no key material, no trust, no stop
	RoleAdmin                    // everything; the local socket only
)

func (r ApiRole) String() string {
	switch r {
	case RoleReadOnly:
		return "read-only"
	case RoleReadWrite:
		return "read-write"
	case RoleAdmin:
		return "admin"
	}
	return "none"
}

// parseNetworkRole parses the role of an access-file client. Only the two
// network roles are accepted: admin exists on the local socket only.
func parseNetworkRole(s string) (ApiRole, error) {
	switch s {
	case "read-only":
		return RoleReadOnly, nil
	case "read-write":
		return RoleReadWrite, nil
	case "admin":
		return RoleNone, errors.New(`role "admin" is available only on the local socket (apiserver.socket); a network client may be read-only or read-write`)
	case "":
		return RoleNone, errors.New("role is required (read-only or read-write)")
	}
	return RoleNone, fmt.Errorf("unknown role %q (read-only or read-write)", s)
}

// AccessFile is the access file as written: what the daemon writes when
// tdns-ncli asks (/access), and a person may edit.
type AccessFile struct {
	// KeyAuth is obsolete: it said whether the API key was still accepted,
	// and there is no API key any more. A file that still has the line
	// loads (the line is ignored, and the daemon says so), and the daemon's
	// next write of the file drops it.
	KeyAuth *bool          `yaml:"keyauth,omitempty"`
	Clients []AccessClient `yaml:"clients"`
}

// AccessClient is one network client: a certificate pin with a name and a role.
type AccessClient struct {
	Name     string `yaml:"name"`
	Pin      string `yaml:"pin"`
	Role     string `yaml:"role"`
	Comment  string `yaml:"comment,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty"`
}

// ParseAccessFile decodes an access file strictly: an unknown key is an error,
// not something silently ignored, because a misspelt "disabled" would leave a
// revoked client enabled.
func ParseAccessFile(data []byte) (*AccessFile, error) {
	var af AccessFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&af); err != nil {
		if errors.Is(err, io.EOF) { // an empty file is an empty policy
			return &af, nil
		}
		return nil, err
	}
	return &af, nil
}

// ValidateAccessFile checks an access file. It is the one validator: the
// daemon runs it at start and reload and on every file it is about to write
// (/access), and the offline `config check` runs it, so they cannot
// disagree.
func ValidateAccessFile(af *AccessFile) error {
	var errs []string
	names := map[string]bool{}
	pins := map[string]string{}
	for i, c := range af.Clients {
		where := fmt.Sprintf("clients[%d]", i)
		if c.Name != "" {
			where = fmt.Sprintf("client %q", c.Name)
		}
		if c.Name == "" {
			errs = append(errs, where+": name is required")
		} else if names[c.Name] {
			errs = append(errs, where+": the name is used twice")
		}
		names[c.Name] = true
		if err := checkSpkiPin(c.Pin); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", where, err))
		} else if other, ok := pins[c.Pin]; ok {
			errs = append(errs, fmt.Sprintf("%s: the pin is also %q's; one certificate, one client", where, other))
		} else {
			pins[c.Pin] = c.Name
		}
		if _, err := parseNetworkRole(c.Role); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", where, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// checkSpkiPin checks that s is a SPKI pin: base64 of a SHA-256 digest, the form
// SPKISHA256 produces and `tdns-cli cert pin` prints. Only the canonical
// spelling: the decoder also takes embedded newlines and nonzero padding
// bits, so several strings name one key. Pins are looked up and compared for
// duplicates as strings, so a variant would never match, and two variants
// would let one key be two clients.
func checkSpkiPin(s string) error {
	if s == "" {
		return errors.New("pin is required")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return fmt.Errorf("pin %q is not a SPKI SHA-256 pin (44 characters of base64)", s)
	}
	return nil
}

// ApiAccessFilePath is the access file of the daemon whose config file is
// cfgfile: configured (apiserver.access-file) when that is set, else
// <config dir>/<config name>-access.yaml, so /etc/tdns/tdns-auth.yaml has
// /etc/tdns/tdns-auth-access.yaml. "" only when neither is known.
func ApiAccessFilePath(configured, cfgfile string) string {
	if configured != "" || cfgfile == "" {
		return configured
	}
	abs, err := filepath.Abs(cfgfile)
	if err != nil {
		return ""
	}
	base := strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs))
	return filepath.Join(filepath.Dir(abs), base+"-access.yaml")
}

// LoadAccessFile reads, decodes and validates the access file at path. A
// file that group or others may write is refused (CheckAccessFileMode). A
// missing file is an error that errors.Is(err, fs.ErrNotExist) recognizes:
// the caller decides that it means no remote clients.
func LoadAccessFile(path string) (*AccessFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := CheckAccessFileMode(path); err != nil {
		return nil, err
	}
	af, err := ParseAccessFile(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := ValidateAccessFile(af); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return af, nil
}

// CheckAccessFileMode refuses an access file that someone other than the
// daemon's user (or root) may change: anyone who can write it can grant
// themselves access. It must be owned by the daemon's user or by root, and
// group and others must not be able to write it. The refusal gives the
// command that fixes it. Pins and roles are not secrets, so reading is
// anyone's: touch under umask 022 makes 0644, which passes. Nothing is
// checked where the platform has no owners.
func CheckAccessFileMode(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	uid, _, ok := fileOwner(fi)
	if !ok {
		return nil
	}
	me := os.Geteuid()
	if uid != me && uid != 0 {
		return fmt.Errorf("access file %s is owned by uid %d, not by\n%s, the daemon's user: whoever owns it can grant\nthemselves access. Fix:\n   chown %s %s",
			path, uid, userName(me), userName(me), path)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("access file %s is writable by group or others\n(mode %04o): whoever can write it can grant themselves\naccess. Fix:\n   chmod go-w %s", path, perm, path)
	}
	return nil
}

// userName is uid's user name, or the number when it has none.
func userName(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(uid)
}

// validateAccessSettings checks apiserver.access-file: an explicit path
// must be absolute (the default is made absolute from the config file).
func (a ApiServerConf) validateAccessSettings() error {
	if a.AccessFile != "" && !filepath.IsAbs(a.AccessFile) {
		return fmt.Errorf("apiserver.access-file %q is not an absolute path", a.AccessFile)
	}
	return nil
}
