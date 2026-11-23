/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * tdns-ncli's side of the management API's access control: the operator's own
 * client certificate (client init), and the daemon's access file (<daemon>
 * client add|list|disable|enable|set-role|keyauth). Design:
 * docs/2026-11-20-api-pinning-mtls-roles-design.md sections 3.3 and 3.7.
 */
package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	tdns "github.com/johanix/tdns/v2"
)

// DefaultClientCertPaths is where the operator's certificate lives when the
// CLI config's client: block does not say: per user, so the key is a person's,
// except for root, whose key is kept in /etc/tdns where it can be tracked
// rather than in /root/.config on every host.
func DefaultClientCertPaths() (cert, key string) {
	if os.Geteuid() == 0 {
		return "/etc/tdns/tdns-ncli-client.crt", "/etc/tdns/tdns-ncli-client.key"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".config", "tdns")
	return filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
}

func clientCertPaths(cc CliClientConf) (string, string) {
	cert, key := DefaultClientCertPaths()
	if cc.Cert != "" {
		cert = cc.Cert
	}
	if cc.Key != "" {
		key = cc.Key
	}
	return cert, key
}

// loadClientCert loads the operator's certificate and key.
func loadClientCert(cc CliClientConf) (*tls.Certificate, error) {
	certPath, keyPath := clientCertPaths(cc)
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("no usable client certificate (%s, %s): %w", certPath, keyPath, err)
	}
	return &c, nil
}

// ---------------------------------------------------------------- client init

// NewClientTopCmd is tdns-ncli's top-level `client`: the operator's own key.
func NewClientTopCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "client",
		Short: "Your own client certificate, for daemons that know you by it",
	}
	c.AddCommand(newClientInitCmd())
	return c
}

func newClientInitCmd() *cobra.Command {
	var certPath, keyPath, name string
	c := &cobra.Command{
		Use:   "init",
		Short: "Create your client certificate (once) and print its pin",
		Long: `Create the key pair a daemon knows you by: a self-signed certificate (ECDSA
P-256) and its key (mode 0600). The default location is ~/.config/tdns/
(for root: /etc/tdns/tdns-ncli-client.crt and .key). An existing pair is never
overwritten; its pin is printed again.

The pin is public. Give it to whoever runs the daemon (or run the printed line
on the daemon's host yourself), then set authmethod: certificate on that
daemon's entry in your CLI config.`,
		Annotations: map[string]string{cliConfigAnnotation: "1"}, // needs no CLI config: it may be the first thing run
		Args:        cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			defCert, defKey := DefaultClientCertPaths()
			if certPath == "" {
				certPath = defCert
			}
			if keyPath == "" {
				keyPath = defKey
			}
			if name == "" {
				name = defaultClientName()
			}
			pin, created, err := ensureClientCert(certPath, keyPath, name)
			if err != nil {
				fatalf("%v", err)
			}
			if created {
				fmt.Printf("Created your client certificate:\n   %s\n   %s (mode 0600)\n", certPath, keyPath)
			} else {
				fmt.Printf("Your client certificate exists (not changed):\n   %s\n", certPath)
			}
			fmt.Printf("\nPin: %s\n\n", pin)
			fmt.Printf("To let a daemon know you, run on its host (as root):\n\n")
			fmt.Printf("   tdns-ncli <daemon> client add %s --pin %s --role read-write\n\n", name, pin)
			fmt.Printf("Then give that daemon's entry in your CLI config:\n\n   authmethod: certificate\n")
			// The client loads the default pair unless client: names
			// another, so a pair made elsewhere needs saying where.
			if certPath != defCert || keyPath != defKey {
				fmt.Printf("\nand, at the top level of the CLI config (the pair is not in the default place):\n\n   client:\n      cert: %s\n      key:  %s\n", certPath, keyPath)
			}
		},
	}
	c.Flags().StringVar(&certPath, "cert", "", "certificate file (default: see above)")
	c.Flags().StringVar(&keyPath, "key", "", "key file (default: see above)")
	c.Flags().StringVar(&name, "name", "", "the name to suggest for you in access files (default: user-host)")
	return c
}

// defaultClientName is "user-host", in the characters an access-file name
// sensibly has.
func defaultClientName() string {
	u := "operator"
	if cu, err := user.Current(); err == nil && cu.Username != "" {
		u = cu.Username
	}
	h, _ := os.Hostname()
	h, _, _ = strings.Cut(h, ".")
	var sb strings.Builder
	for _, r := range strings.ToLower(u + "-" + h) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	return strings.Trim(sb.String(), "-")
}

// ensureClientCert creates the key pair if the certificate does not exist and
// returns its pin. It never overwrites.
func ensureClientCert(certPath, keyPath, cn string) (pin string, created bool, err error) {
	if data, err := os.ReadFile(certPath); err == nil {
		p, perr := pemCertPin(data)
		if perr != nil {
			return "", false, fmt.Errorf("%s exists but %v", certPath, perr)
		}
		// The pair, not the certificate alone: a pin for a certificate
		// whose key is gone or another one would enrol a client that can
		// never connect. Touch neither file.
		if _, kerr := tls.LoadX509KeyPair(certPath, keyPath); kerr != nil {
			return "", false, fmt.Errorf("%s exists, but it and %s are not a usable pair (%v); not touching either: fix the key, or remove both and run client init again",
				certPath, keyPath, kerr)
		}
		return p, false, nil
	}
	if _, err := os.Stat(keyPath); err == nil {
		return "", false, fmt.Errorf("%s exists without its certificate %s; not overwriting a key", keyPath, certPath)
	}
	for _, d := range []string{filepath.Dir(certPath), filepath.Dir(keyPath)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", false, err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", false, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", false, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		// The pin, not the validity period, is what a daemon trusts.
		NotAfter:    time.Now().AddDate(10, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", false, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", false, err
	}
	// The key first: a certificate without its key would make the next run
	// believe the pair exists. Both created exclusively: two client inits at
	// once both pass the checks above, and with a plain write the second
	// would replace the first one's key, or leave one run's key with the
	// other's certificate. With O_EXCL the second fails instead.
	if err := createNewFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return "", false, err
	}
	if err := createNewFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		os.Remove(keyPath) // this call created it
		return "", false, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return "", false, err
	}
	return tdns.SPKISHA256(leaf), true, nil
}

// createNewFile writes data to path, which must not exist yet. A write that
// fails removes the file it created, and nothing else.
func createNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func pemCertPin(data []byte) (string, error) {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return "", errors.New("holds no certificate")
		}
		if b.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return "", err
			}
			return tdns.SPKISHA256(c), nil
		}
	}
}

// ------------------------------------------------- <daemon> client ... commands

// accessTarget is where a daemon's access file is, as its daemon config says.
type accessTarget struct {
	DaemonConfig string
	File         string // apiserver.access-file, or the suggested path when unset
	Configured   bool   // the daemon config names it, so the daemon reads it
	HasSocket    bool
	Socket       string // apiserver.socket, the daemon's local admin socket, or ""
}

// resolveAccessTarget finds role's daemon config and its access file. The
// client commands edit files on this host, so a daemon whose config is not
// here is refused.
func resolveAccessTarget(role string) (*accessTarget, error) {
	cfg := defaultCfgFileForRole(role)
	if _, err := os.Stat(cfg); err != nil {
		return nil, fmt.Errorf("cannot read %s's daemon config %s (%v); the client commands edit the daemon's files, so run them on its host", role, cfg, err)
	}
	info, err := ReadDaemonApi(cfg, effectiveRole(role))
	if err != nil {
		return nil, err
	}
	// Without config-file: the daemon config above is only this host's
	// default for the role, and the role's entry may reach another daemon
	// altogether: editing and reloading the local daemon would then leave
	// the one the operator meant unchanged. A TCP address cannot settle
	// which daemon answers on it (another one may hold it while this one
	// runs on its socket alone), so only the daemon's own socket identifies
	// it; any other entry needs config-file:, which config add writes.
	if ad := apiDetailsForRole(role); ad != nil && ad.ConfigFile == "" && !entryIsDaemonSocket(*ad, info) {
		return nil, fmt.Errorf("%s's entry %s (%s) has no config-file:, so nothing says it is the daemon of %s; the client commands edit a daemon's own files, and an address does not tell which daemon answers on it. Give the entry config-file: (tdns-ncli config add writes it), or use the daemon's local socket entry",
			role, ad.Name, ad.BaseURL, cfg)
	}
	t := &accessTarget{DaemonConfig: info.ConfigFile, File: info.AccessFile, Configured: info.AccessFile != "", HasSocket: info.Socket != "", Socket: info.Socket}
	if !t.Configured {
		base := strings.TrimSuffix(filepath.Base(info.ConfigFile), filepath.Ext(info.ConfigFile))
		t.File = filepath.Join(filepath.Dir(info.ConfigFile), base+"-access.yaml")
	}
	return t, nil
}

// entryIsDaemonSocket says whether entry e is the local socket of the daemon
// whose API is info. The socket is the daemon's own: it creates it, in a
// directory only it may use, and refuses one that another process holds. A
// TCP address is not like that, so it identifies no daemon by itself.
func entryIsDaemonSocket(e ApiDetails, info *DaemonApi) bool {
	u, err := url.Parse(e.BaseURL)
	if err != nil || !strings.EqualFold(u.Scheme, "unix") {
		return false
	}
	return info.Socket != "" && u.Path == info.Socket
}

type accessEditOpts struct {
	DryRun   bool
	NoReload bool
}

// editAccessFile is the one way the client commands change an access file:
// read it, apply change, validate the result with the daemon's own validator,
// write it atomically keeping the previous one as .prev, and reload.
func editAccessFile(ctx context.Context, role string, o accessEditOpts, create bool, change func(af *tdns.AccessFile) (string, error)) error {
	t, err := resolveAccessTarget(role)
	if err != nil {
		return err
	}
	// From before the read to after the write (and the reload): two edits
	// that both read the old file would each write their own change over
	// the other's, so a `client disable` could be undone by a `client add`
	// that started earlier, and both would report success. The lock
	// `config add` uses, on the access file. A dry run writes nothing and
	// takes no lock.
	if !o.DryRun {
		if ctx == nil {
			ctx = context.Background()
		}
		unlock, err := lockCliConfig(ctx, t.File)
		if err != nil {
			return err
		}
		defer unlock()
	}
	af := &tdns.AccessFile{}
	old, rerr := os.ReadFile(t.File)
	switch {
	case rerr == nil:
		if af, err = tdns.ParseAccessFile(old); err != nil {
			return fmt.Errorf("%s does not parse (%v); fix it by hand first", t.File, err)
		}
	case os.IsNotExist(rerr) && create:
		old = nil
	case os.IsNotExist(rerr):
		return fmt.Errorf("%s does not exist yet; `client add` creates it", t.File)
	default:
		return rerr
	}

	msg, err := change(af)
	if err != nil {
		return err
	}
	// The daemon's own validator: the tool cannot write a file the daemon
	// would refuse.
	if err := tdns.ValidateAccessFile(af); err != nil {
		return fmt.Errorf("not writing %s: %v", t.File, err)
	}
	out, err := renderAccessFile(af, t.DaemonConfig)
	if err != nil {
		return err
	}
	if o.DryRun {
		fmt.Printf("Would write %s:\n\n%s", t.File, out)
		return nil
	}
	// Whatever answers on the daemon's socket (or the role's entry) may be
	// another daemon (one that holds this config's socket path, say):
	// writing this file then changes nothing the operator meant, reload or
	// not. So before writing, the daemon there must say it runs this config.
	if err := verifyRunningDaemon(role, t); err != nil {
		return err
	}
	if err := writeAccessFile(t.File, old, out, t.DaemonConfig); err != nil {
		return err
	}
	fmt.Println(msg)

	if !t.Configured {
		fmt.Printf("\n%s does not read %s yet. Add under apiserver: in %s:\n\n", role, t.File, t.DaemonConfig)
		if !t.HasSocket {
			fmt.Printf("   socket:      /var/run/tdns/%s.sock\n", strings.TrimSuffix(filepath.Base(t.DaemonConfig), filepath.Ext(t.DaemonConfig)))
		}
		fmt.Printf("   access-file: %s\n\nthen reload the daemon over its local socket. Until then the clients here do nothing.\n", t.File)
		return nil
	}
	if o.NoReload {
		fmt.Printf("Not reloaded (--no-reload): the daemon still runs the previous file.\n")
		return nil
	}
	return reloadForAccess(role, t.Socket)
}

// reloadForAccess asks role's daemon to reload its config, and with it the
// access file. A refused reload changes nothing in the daemon.
func reloadForAccess(role, socket string) error {
	resp, err := configToDaemon(role, socket, tdns.ConfigPost{Command: "reload"})
	if err != nil {
		return fmt.Errorf("written, but the reload failed: %v", err)
	}
	return accessReloadVerdict(resp)
}

// configToDaemon sends post to role's daemon over its local socket first, when
// there is one: it is admin, needs no network credentials, and answers when
// the TCP API does not (a daemon that started with a broken access file
// answers 503 on TCP until a reload fixes it; with keyauth off the role's key
// entry is refused). Only when the socket cannot be used from here (not root:
// EACCES; or nothing is running) does the role's own entry get it instead.
func configToDaemon(role, socket string, post tdns.ConfigPost) (tdns.ConfigResponse, error) {
	if socket != "" {
		resp, err := SendConfigCommand(tdns.NewClient(role, "unix://"+socket, "", "none", ""), post)
		if err == nil {
			return resp, nil
		}
		if !socketUnusable(err) {
			return resp, fmt.Errorf("over the local socket %s: %w", socket, err)
		}
	}
	api, err := GetApiClient(role, false)
	if err != nil {
		return tdns.ConfigResponse{}, err
	}
	return SendConfigCommand(api, post)
}

// verifyRunningDaemon checks that the daemon on t's socket, and the one the
// role's entry reaches, runs t's daemon config. Nothing running is fine (the
// next start reads the file): that is no socket file or a refused
// connection, on the socket and then on the entry. Anything else is refused
// before a byte is written: a daemon that runs another config or does not
// say which, and one that is there but cannot be asked (a socket that is not
// ours to open, a TCP entry it refuses), as that one is not identified.
func verifyRunningDaemon(role string, t *accessTarget) error {
	post := tdns.ConfigPost{Command: "status"}
	if t.Socket != "" {
		resp, err := SendConfigCommand(tdns.NewClient(role, "unix://"+t.Socket, "", "none", ""), post)
		switch {
		case err == nil:
			return runsConfig(resp, t)
		case !nothingListening(err):
			return fmt.Errorf("cannot ask the daemon on %s which config it runs (%v), so it is not known whose file this is; not editing %s (run as root, or as the daemon's user)",
				t.Socket, err, t.File)
		}
	}
	// Nothing on the socket. A daemon may still run without it (it refuses
	// a socket another process holds): ask through the role's entry.
	// No entry for the role: nobody else to ask. An entry that cannot be
	// built (a CA file or client certificate it cannot read) is not that:
	// its daemon may well be running, and it is not identified.
	if apiDetailsForRole(role) == nil {
		return nil
	}
	api, err := GetApiClient(role, false)
	if err != nil {
		return fmt.Errorf("cannot ask the daemon of %s's entry which config it runs (%v), so it is not known whose file this is; not editing %s",
			role, err, t.File)
	}
	resp, err := SendConfigCommand(api, post)
	switch {
	case err == nil:
		return runsConfig(resp, t)
	case nothingListening(err):
		return nil
	}
	return fmt.Errorf("cannot ask the daemon at %s which config it runs (%v), so it is not known whose file this is; not editing %s",
		api.BaseUrl, err, t.File)
}

// nothingListening says whether err means nobody is there: no socket file,
// or a refused connection. Not a socket we may not open, which someone holds.
func nothingListening(err error) bool {
	return errors.Is(err, syscall.ENOENT) || strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

// runsConfig checks that the daemon whose status is resp runs t's config.
func runsConfig(resp tdns.ConfigResponse, t *accessTarget) error {
	if resp.ConfigFile == "" {
		return fmt.Errorf("the daemon that answers does not say which config it runs; not editing %s", t.File)
	}
	if resolvedPath(resp.ConfigFile) != resolvedPath(t.DaemonConfig) {
		return fmt.Errorf("the daemon that answers runs %s, not %s (do two daemons share a socket or an address?); not editing %s",
			resp.ConfigFile, t.DaemonConfig, t.File)
	}
	return nil
}

// socketUnusable says whether a request over the local socket failed because
// the socket cannot be used from here (not ours to open, or no daemon on it),
// not because the daemon answered.
func socketUnusable(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.ENOENT) ||
		strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

// accessReloadVerdict says whether the reload put the edited access file in
// force. The daemon's reload succeeds even when the access file does not load
// (it keeps the running policy), so its reply text is the only sign; a
// `client disable` must not report success while the client keeps its access.
func accessReloadVerdict(resp tdns.ConfigResponse) error {
	if resp.Error {
		return fmt.Errorf("written, but the daemon refused the reload: %s", resp.ErrorMsg)
	}
	if strings.Contains(resp.Msg, tdns.AccessFileNotReloaded) {
		return fmt.Errorf("written, but the daemon did NOT apply it and keeps the previous policy: %s", strings.TrimSpace(resp.Msg))
	}
	fmt.Printf("Reloaded: %s\n", strings.TrimSpace(resp.Msg))
	return nil
}

// renderAccessFile writes the file as tdns-ncli owns it: a header, keyauth
// spelled out, and the clients. Comments a person adds are not kept; notes go
// in a client's comment:.
func renderAccessFile(af *tdns.AccessFile, daemonConfig string) ([]byte, error) {
	keyauth := af.KeyAuthOn()
	out := tdns.AccessFile{KeyAuth: &keyauth, Clients: af.Clients}
	if out.Clients == nil {
		out.Clients = []tdns.AccessClient{}
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Access file of the management API of %s.\n", daemonConfig)
	fmt.Fprintf(&buf, "# Written by tdns-ncli (<daemon> client ...). Hand edits work, but comments\n")
	fmt.Fprintf(&buf, "# are not kept: put notes in a client's comment:. Roles: read-only, read-write\n")
	fmt.Fprintf(&buf, "# (admin is the local socket's alone). keyauth: false turns the API key off.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(3)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	enc.Close()
	return buf.Bytes(), nil
}

// writeAccessFile replaces path atomically (following a symlink, keeping the
// file's mode, owner and group), after saving the previous content as
// path.prev. A new file takes the daemon config's mode, owner and group, so
// the daemon can read it as it reads that. Atomic for a new file too: the
// daemon reads this file at start and at every reload, and a truncated one
// parses (keyauth on, no clients).
func writeAccessFile(path string, old, data []byte, daemonConfig string) error {
	if old != nil {
		if err := os.WriteFile(path+".prev", old, 0o600); err != nil {
			return fmt.Errorf("saving %s.prev: %w", path, err)
		}
		return writeFileAtomicLike(path, data, nil)
	}
	var like os.FileInfo
	if fi, err := os.Stat(daemonConfig); err == nil {
		like = fi
	}
	return writeFileAtomicLike(path, data, like)
}

func findClient(af *tdns.AccessFile, name string) *tdns.AccessClient {
	for i := range af.Clients {
		if af.Clients[i].Name == name {
			return &af.Clients[i]
		}
	}
	return nil
}

// NewClientCmd is the `client` subtree of one daemon's command tree.
func NewClientCmd(role string) *cobra.Command {
	var o accessEditOpts
	c := &cobra.Command{
		Use:   "client",
		Short: fmt.Sprintf("Manage who may use %s's management API over the network (its access file)", role),
		Long: fmt.Sprintf(`Manage %s's access file: the network clients, by the pin of their
certificate, with their roles, and whether the API key still works. Run on the
daemon's host. Every change is checked with the daemon's own validator, written
atomically (the previous file is kept as .prev), and followed by a reload.

Roles are read-only and read-write. Admin is the local socket's alone.`, role),
	}
	c.PersistentFlags().BoolVar(&o.DryRun, "dry-run", false, "show the resulting file; change nothing")
	c.PersistentFlags().BoolVar(&o.NoReload, "no-reload", false, "write the file but do not ask the daemon to reload it")

	var pin, certFile, roleName, comment string
	add := &cobra.Command{
		Use:   "add <name> (--pin P | --cert F) --role read-only|read-write",
		Short: "Add a client: a name, the pin of its certificate, and a role",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			p := pin
			switch {
			case p != "" && certFile != "":
				fatalf("give --pin or --cert, not both")
			case certFile != "":
				data, err := os.ReadFile(certFile)
				if err != nil {
					fatalf("%v", err)
				}
				if p, err = pemCertPin(data); err != nil {
					fatalf("%s %v", certFile, err)
				}
			case p == "":
				fatalf("give the client's pin (--pin) or its certificate (--cert); never its key")
			}
			if roleName == "" {
				fatalf("--role read-only|read-write is required")
			}
			if strings.ContainsAny(name, " \t") {
				fatalf("a client name has no spaces")
			}
			err := editAccessFile(cmd.Context(), role, o, true, func(af *tdns.AccessFile) (string, error) {
				if findClient(af, name) != nil {
					return "", fmt.Errorf("%q is already there; use set-role, enable or disable", name)
				}
				af.Clients = append(af.Clients, tdns.AccessClient{Name: name, Pin: p, Role: roleName, Comment: comment})
				return fmt.Sprintf("Added %s (%s).", name, roleName), nil
			})
			if err != nil {
				fatalf("%v", err)
			}
		},
	}
	add.Flags().StringVar(&pin, "pin", "", "the SPKI pin of the client's certificate (tdns-ncli client init prints it)")
	add.Flags().StringVar(&certFile, "cert", "", "the client's certificate (public); its pin is computed")
	add.Flags().StringVar(&roleName, "role", "", "read-only or read-write")
	add.Flags().StringVar(&comment, "comment", "", "a note kept with the entry")

	setDisabled := func(use, short string, disabled bool) *cobra.Command {
		return &cobra.Command{
			Use:   use + " <name>",
			Short: short,
			Args:  cobra.ExactArgs(1),
			Run: func(cmd *cobra.Command, args []string) {
				err := editAccessFile(cmd.Context(), role, o, false, func(af *tdns.AccessFile) (string, error) {
					cl := findClient(af, args[0])
					if cl == nil {
						return "", fmt.Errorf("no client %q", args[0])
					}
					cl.Disabled = disabled
					return fmt.Sprintf("%s: %s.", args[0], map[bool]string{true: "disabled", false: "enabled"}[disabled]), nil
				})
				if err != nil {
					fatalf("%v", err)
				}
			},
		}
	}

	setRole := &cobra.Command{
		Use:   "set-role <name> read-only|read-write",
		Short: "Change a client's role",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			err := editAccessFile(cmd.Context(), role, o, false, func(af *tdns.AccessFile) (string, error) {
				cl := findClient(af, args[0])
				if cl == nil {
					return "", fmt.Errorf("no client %q", args[0])
				}
				cl.Role = args[1]
				return fmt.Sprintf("%s is now %s.", args[0], args[1]), nil
			})
			if err != nil {
				fatalf("%v", err)
			}
		},
	}

	keyauth := &cobra.Command{
		Use:   "keyauth on|off",
		Short: "Accept the API key on the TCP API (read-write), or not",
		Long: `keyauth off stops the API key working on the TCP API: clients then need a
certificate. It cannot lock anyone out, because the local socket does not
depend on it. keyauth on brings the key back.`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"on", "off"},
		Run: func(cmd *cobra.Command, args []string) {
			var on bool
			switch args[0] {
			case "on":
				on = true
			case "off":
			default:
				fatalf("keyauth on or off")
			}
			err := editAccessFile(cmd.Context(), role, o, true, func(af *tdns.AccessFile) (string, error) {
				af.KeyAuth = &on
				if on {
					return "keyauth on: the API key works on the TCP API (as read-write).", nil
				}
				enabled := 0
				for _, c := range af.Clients {
					if !c.Disabled {
						enabled++
					}
				}
				msg := "keyauth off: the TCP API now needs a client certificate. The local socket is unaffected."
				if enabled == 0 {
					msg += " There is no enabled client, so the TCP API is closed to everyone but the socket."
				}
				return msg, nil
			})
			if err != nil {
				fatalf("%v", err)
			}
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List the clients in the access file, and whether the daemon runs that file",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := listAccessClients(role); err != nil {
				fatalf("%v", err)
			}
		},
	}

	c.AddCommand(add,
		setDisabled("disable", "Refuse a client, keeping its entry", true),
		setDisabled("enable", "Accept a disabled client again", false),
		setRole, keyauth, list)
	return c
}

// listAccessClients prints the file and compares it with what the daemon is
// running (config status), so an edit that was not reloaded shows.
func listAccessClients(role string) error {
	t, err := resolveAccessTarget(role)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(t.File)
	if err != nil {
		return err
	}
	af, err := tdns.ParseAccessFile(data)
	if err != nil {
		return fmt.Errorf("%s does not parse: %v", t.File, err)
	}
	fmt.Printf("Access file: %s\n", t.File)
	if !t.Configured {
		fmt.Printf("(%s does not name it in apiserver.access-file, so the daemon does not read it)\n", t.DaemonConfig)
	}
	fmt.Printf("keyauth: %s\n\n", map[bool]string{true: "on", false: "off"}[af.KeyAuthOn()])
	for _, c := range af.Clients {
		state := ""
		if c.Disabled {
			state = ", disabled"
		}
		note := ""
		if c.Comment != "" {
			note = "  # " + c.Comment
		}
		fmt.Printf("   %-20s %-11s pin %s%s%s\n", c.Name, c.Role, c.Pin, state, note)
	}

	if !t.Configured {
		return nil
	}
	// Over the socket first, as the reload: after `client keyauth off` the
	// role's key entry is refused, but the socket still answers.
	resp, err := configToDaemon(role, t.Socket, tdns.ConfigPost{Command: "status"})
	if err != nil || resp.Error {
		fmt.Printf("\nRunning policy unknown: %v %s\n", err, resp.ErrorMsg)
		return nil
	}
	// Whoever answered must be this config's daemon: another one on the
	// socket would report its own policy, and a match would say "runs
	// this file" of a daemon that does not.
	if err := runsConfig(resp, t); err != nil {
		fmt.Printf("\nRunning policy unknown: %v\n", err)
		return nil
	}
	if resp.Access == nil {
		fmt.Printf("\nThe daemon runs no access file (pending reload?).\n")
		return nil
	}
	if resp.Access.Error != "" {
		fmt.Printf("\nThe daemon could not use its access file at start-up: %s\n", resp.Access.Error)
		return nil
	}
	if accessMatchesRunning(af, resp.Access) {
		fmt.Printf("\nThe daemon runs this file.\n")
	} else {
		fmt.Printf("\nPENDING RELOAD: the daemon runs a different policy (%d client(s), keyauth %s).\n",
			len(resp.Access.Clients), map[bool]string{true: "on", false: "off"}[resp.Access.KeyAuth])
	}
	return nil
}

func accessMatchesRunning(af *tdns.AccessFile, run *tdns.ApiAccessStatus) bool {
	if af.KeyAuthOn() != run.KeyAuth || len(af.Clients) != len(run.Clients) {
		return false
	}
	for i, c := range af.Clients {
		r := run.Clients[i]
		if c.Name != r.Name || c.Pin != r.Pin || c.Role != r.Role || c.Disabled != r.Disabled {
			return false
		}
	}
	return true
}
