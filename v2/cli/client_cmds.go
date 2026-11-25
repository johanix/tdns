/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * tdns-ncli's side of the management API's access control: the operator's own
 * client certificate (client init), and the daemon's access file (<daemon>
 * client add|list|disable|enable|set-role|keyauth), which the daemon writes
 * when asked over its local socket (/access). Design:
 * docs/2026-11-20-api-pinning-mtls-roles-design.md sections 3.3 and 3.7, and
 * docs/2026-11-25-tdns-ncli-cert-setup-design.md section 3.
 */
package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

// DefaultClientCertPaths is where the operator's certificate lives when the
// CLI config's client: block does not say: per user, so the key is a person's,
// except for root, whose key is kept in /etc/tdns/certs where it can be
// tracked rather than in /root/.config on every host. Always in a certs/
// directory, where certificates and keys are looked for, never loose next to
// the configs.
func DefaultClientCertPaths() (cert, key string) {
	if os.Geteuid() == 0 {
		return "/etc/tdns/certs/tdns-ncli-client.crt", "/etc/tdns/certs/tdns-ncli-client.key"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".config", "tdns", "certs")
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
P-256) and its key (mode 0600). The default location is ~/.config/tdns/certs/
(for root: /etc/tdns/certs/tdns-ncli-client.crt and .key). An existing pair is never
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
				fmt.Printf("\nand, at the top level of the CLI config (the pair is not in the default place):\n\n   client:\n      cert: %s\n      key:  %s\n", yamlScalar(certPath), yamlScalar(keyPath))
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

// daemonSocketClient is a client for the local admin socket of role's
// daemon: the daemon of daemonCfg (--daemon-config) when it is set, else of
// the role's daemon config (its entry's config-file:, else the default).
// Every request names that config, so another daemon on the socket refuses
// it (412) before it acts on it.
func daemonSocketClient(role, daemonCfg string) (*tdns.ApiClient, error) {
	cfg := daemonCfg
	if cfg == "" {
		cfg = defaultCfgFileForRole(role)
	}
	info, err := ReadDaemonApi(cfg, effectiveRole(role))
	// An entry without config-file: may reach another daemon altogether;
	// only the default daemon's own socket says it is that daemon.
	if ad := apiDetailsForRole(role); daemonCfg == "" && ad != nil && ad.ConfigFile == "" &&
		(err != nil || !entryIsDaemonSocket(*ad, info)) {
		why := ""
		if err != nil {
			why = "\nReading the default daemon config failed:\n" + err.Error()
		}
		return nil, fmt.Errorf("the entry %s has no config-file:, so nothing says\nwhich daemon it is. Give --daemon-config <file>, or add\nconfig-file: to the entry%s", ad.Name, why)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s's daemon config %s: %v", role, cfg, err)
	}
	if info.Socket == "" {
		return nil, fmt.Errorf("%s serves no local admin socket\n(socket: none), which this command needs", info.ConfigFile)
	}
	return tdns.NewClientWithOptions(role, "unix://"+info.Socket,
		tdns.ClientOptions{AuthMethod: "none", ExpectConfigFile: info.ConfigFile}), nil
}

// entryIsDaemonSocket says whether entry e is the local socket of the daemon
// whose API is info. The socket is the daemon's own: it creates it, in a
// directory only it may use. A TCP address identifies no daemon by itself.
func entryIsDaemonSocket(e ApiDetails, info *DaemonApi) bool {
	u, err := url.Parse(e.BaseURL)
	if err != nil || !strings.EqualFold(u.Scheme, "unix") {
		return false
	}
	return info.Socket != "" && u.Path == info.Socket
}

// socketError says plainly when the local socket sock cannot be used from
// here (not ours to open, or no daemon there). Any other err, a daemon's
// refusal among them, is returned as it is.
func socketError(sock string, err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.EACCES || errno == syscall.EPERM ||
		errno == syscall.ENOENT || errno == syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot use the daemon's local socket (%v):\n   %s\nThe client commands need the running daemon and its local\nsocket: run them as root on the daemon's host", errno, sock)
	}
	return err
}

// configAtDaemon sends post to the daemon of daemonCfg over its local admin
// socket (config reload --daemon-config), which needs no CLI config.
func configAtDaemon(role, daemonCfg string, post tdns.ConfigPost) (tdns.ConfigResponse, error) {
	c, err := daemonSocketClient(role, daemonCfg)
	if err != nil {
		return tdns.ConfigResponse{}, err
	}
	resp, err := SendConfigCommand(c, post)
	if err != nil && !resp.Error {
		err = socketError(c.Socket, err)
	}
	return resp, err
}

// accessAtDaemon sends post to role's daemon (see daemonSocketClient), which
// writes its access file and answers with what is in force.
func accessAtDaemon(role, daemonCfg string, post tdns.AccessPost) (tdns.AccessResponse, error) {
	var resp tdns.AccessResponse
	c, err := daemonSocketClient(role, daemonCfg)
	if err != nil {
		return resp, err
	}
	body, err := json.Marshal(post)
	if err != nil {
		return resp, err
	}
	status, buf, err := c.Post("/access", body)
	switch {
	case status == http.StatusNotFound:
		return resp, errors.New("the daemon has no /access route: is it older than tdns-ncli?")
	case err != nil:
		return resp, socketError(c.Socket, err)
	}
	if err := json.Unmarshal(buf, &resp); err != nil {
		return resp, fmt.Errorf("the daemon's answer (HTTP %d) does not parse: %v", status, err)
	}
	return resp, nil
}

// runAccess sends post to role's daemon and prints its verdict, in its own
// words. A refusal is the error.
func runAccess(role, daemonCfg string, post tdns.AccessPost) error {
	resp, err := accessAtDaemon(role, daemonCfg, post)
	switch {
	case err != nil:
		return err
	case resp.Error:
		return errors.New(resp.ErrorMsg)
	}
	if post.Command == "list" {
		printAccessList(resp)
		return nil
	}
	fmt.Println(resp.Msg)
	if resp.Rendered != "" {
		fmt.Printf("\n%s", resp.Rendered)
	}
	return nil
}

// printAccessList prints what the daemon runs: the verdict, the access file,
// keyauth, the clients, and the pins of the certificate its TCP API serves.
func printAccessList(resp tdns.AccessResponse) {
	fmt.Println(resp.Msg)
	if resp.File != "" {
		fmt.Printf("\nAccess file: %s\n", resp.File)
		fmt.Printf("keyauth: %s\n\n", map[bool]string{true: "on", false: "off"}[resp.KeyAuth])
		for _, c := range resp.Clients {
			state, note := "", ""
			if c.Disabled {
				state = ", disabled"
			}
			if c.Comment != "" {
				note = "  # " + c.Comment
			}
			fmt.Printf("   %-20s %-11s pin %s%s%s\n", c.Name, c.Role, c.Pin, state, note)
		}
	}
	if len(resp.ServerPins) == 0 {
		fmt.Printf("\nServer pins: none (no TLS listener on the TCP API)\n")
		return
	}
	fmt.Printf("\nServer pins (the certificate the TCP API serves):\n")
	for _, p := range resp.ServerPins {
		fmt.Printf("   %s\n", p)
	}
}

// NewClientCmd is the `client` subtree of one daemon's command tree.
func NewClientCmd(role string) *cobra.Command {
	var dryRun bool
	var daemonCfg string
	c := &cobra.Command{
		Use:   "client",
		Short: fmt.Sprintf("Manage who may use %s's management API over the network (its access file)", role),
		Long: fmt.Sprintf(`Manage %s's access file: the network clients, by the pin of their
certificate, with their roles, and whether the API key still works.

The daemon writes the file. Each command goes to the running daemon over
its local admin socket, so run them as root on the daemon's host. The
daemon checks every change with its validator, writes it atomically (the
previous file is kept as .prev) and puts it in force at once.

Roles are read-only and read-write. Admin is the local socket's alone.`, role),
	}
	c.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "show the resulting file; change nothing")
	c.PersistentFlags().StringVar(&daemonCfg, "daemon-config", "",
		"the daemon's config file (default: the one the role's entry names, else the role's default)")
	c.PersistentFlags().Bool("no-reload", false, "ignored")
	_ = c.PersistentFlags().MarkDeprecated("no-reload", "the daemon puts every change it writes in force; the flag is ignored")
	send := func(post tdns.AccessPost) {
		post.DryRun = dryRun
		if err := runAccess(role, daemonCfg, post); err != nil {
			fatalf("%v", err)
		}
	}

	var pin, certFile, roleName, comment string
	add := &cobra.Command{
		Use:   "add <name> (--pin P | --cert F) --role read-only|read-write",
		Short: "Add a client: a name, the pin of its certificate, and a role",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
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
			send(tdns.AccessPost{Command: "add", Name: args[0], Pin: p, Role: roleName, Comment: comment})
		},
	}
	add.Flags().StringVar(&pin, "pin", "", "the SPKI pin of the client's certificate (tdns-ncli client init prints it)")
	add.Flags().StringVar(&certFile, "cert", "", "the client's certificate (public); its pin is computed")
	add.Flags().StringVar(&roleName, "role", "", "read-only or read-write")
	add.Flags().StringVar(&comment, "comment", "", "a note kept with the entry")

	setDisabled := func(use, short string) *cobra.Command {
		return &cobra.Command{
			Use:   use + " <name>",
			Short: short,
			Args:  cobra.ExactArgs(1),
			Run: func(cmd *cobra.Command, args []string) {
				send(tdns.AccessPost{Command: use, Name: args[0]})
			},
		}
	}

	setRole := &cobra.Command{
		Use:   "set-role <name> read-only|read-write",
		Short: "Change a client's role",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			send(tdns.AccessPost{Command: "set-role", Name: args[0], Role: args[1]})
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
			send(tdns.AccessPost{Command: "keyauth", KeyAuth: args[0]})
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List the clients the daemon runs, and the pins of its TCP API certificate",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := runAccess(role, daemonCfg, tdns.AccessPost{Command: "list"}); err != nil {
				fatalf("%v", err)
			}
		},
	}

	c.AddCommand(add,
		setDisabled("disable", "Refuse a client, keeping its entry"),
		setDisabled("enable", "Accept a disabled client again"),
		setRole, keyauth, list)
	return c
}
