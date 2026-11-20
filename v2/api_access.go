/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The access file of the network management API: who may connect over TCP,
 * with which role, and whether the API key still works. Design:
 * docs/2026-11-20-api-pinning-mtls-roles-design.md sections 3.3 and 4.
 */
package tdns

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// AccessFile is the access file as written: what tdns-ncli writes and a
// person may edit.
type AccessFile struct {
	// KeyAuth says whether the API key is still accepted. Absent means true.
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

// KeyAuthOn is KeyAuth with its default applied.
func (af *AccessFile) KeyAuthOn() bool { return af.KeyAuth == nil || *af.KeyAuth }

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
// daemon runs it at start and reload, the offline `config check` runs it, and
// tdns-ncli runs it on every file it is about to write, so the three cannot
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
			errs = append(errs, fmt.Sprintf("%s: the pin is also %q's; one key, one client", where, other))
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
// SPKISHA256 produces and `tdns-cli cert pin` prints.
func checkSpkiPin(s string) error {
	if s == "" {
		return errors.New("pin is required")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("pin %q is not a SPKI SHA-256 pin (44 characters of base64)", s)
	}
	return nil
}

// LoadAccessFile reads, decodes and validates the access file at path.
func LoadAccessFile(path string) (*AccessFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
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

// validateAccessSettings checks the apiserver: keys that go with the access
// file. With an access file the API key is capped at read-write and admin
// exists only on the local socket, so an access file without a socket would
// leave nothing able to do admin work.
func (a ApiServerConf) validateAccessSettings() error {
	if a.AccessFile != "" && a.Socket == "" {
		return fmt.Errorf("apiserver.access-file %s requires apiserver.socket: with an access file, admin is available only on the local socket", a.AccessFile)
	}
	if a.AccessFile != "" && !filepath.IsAbs(a.AccessFile) {
		return fmt.Errorf("apiserver.access-file %q is not an absolute path", a.AccessFile)
	}
	return nil
}
