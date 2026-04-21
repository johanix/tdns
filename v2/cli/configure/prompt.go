/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Bootstrap-configure library: interactive prompt primitives.
 *
 * Apps use these to build their role-specific interview flow.
 * Stdin-based; for empty-input behaviour see Ask.
 */
package configure

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Validator returns nil on valid input, or an error describing
// what is wrong. The prompter will re-prompt on error.
type Validator func(string) error

// Prompter is a thin wrapper around bufio.Reader / io.Writer so
// tests can stub stdin/stdout. Construct with NewPrompter (which
// binds to os.Stdin / os.Stdout) or build a struct literal for
// tests.
type Prompter struct {
	In  *bufio.Reader
	Out io.Writer
}

// NewPrompter returns a Prompter bound to os.Stdin / os.Stdout.
func NewPrompter() *Prompter {
	return &Prompter{In: bufio.NewReader(os.Stdin), Out: os.Stdout}
}

// Ask shows `label`, pre-filled with `dflt`. Empty input accepts
// the default. The validator runs on the effective value;
// failure re-prompts.
func (p *Prompter) Ask(label, dflt string, v Validator) string {
	for {
		if dflt != "" {
			fmt.Fprintf(p.Out, "%s [%s]: ", label, dflt)
		} else {
			fmt.Fprintf(p.Out, "%s: ", label)
		}
		line, err := p.In.ReadString('\n')
		if err != nil && line == "" {
			return ""
		}
		val := strings.TrimSpace(line)
		if val == "" {
			val = dflt
		}
		if v != nil {
			if vErr := v(val); vErr != nil {
				fmt.Fprintf(p.Out, "  invalid: %v\n", vErr)
				continue
			}
		}
		return val
	}
}

// AskIdentity accepts a bare name, canonicalises it via
// dns.Fqdn, echoes the canonical form, and returns it.
func (p *Prompter) AskIdentity(label, dflt string) string {
	raw := p.Ask(label, dflt, NonEmpty("identity"))
	fq := dns.Fqdn(strings.TrimSpace(raw))
	if fq != raw {
		fmt.Fprintf(p.Out, "  using %s\n", fq)
	}
	return fq
}

// AskYesNo prompts [Y/n] / [y/N]. Empty input returns
// `defaultYes`. Any non-"n"-starting answer counts as yes.
func (p *Prompter) AskYesNo(label string, defaultYes bool) bool {
	tag := "[Y/n]"
	if !defaultYes {
		tag = "[y/N]"
	}
	fmt.Fprintf(p.Out, "%s %s: ", label, tag)
	line, err := p.In.ReadString('\n')
	if err != nil && line == "" {
		return defaultYes
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	if ans == "" {
		return defaultYes
	}
	return ans[0] != 'n'
}

// --- Standard validators ---

// NonEmpty rejects blank input, labelling errors with `field`.
func NonEmpty(field string) Validator {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
}

// AbsDir requires an absolute path.
func AbsDir(s string) error {
	if err := NonEmpty("directory")(s); err != nil {
		return err
	}
	if !strings.HasPrefix(s, "/") {
		return fmt.Errorf("must be an absolute path")
	}
	return nil
}

// HostPort requires "host:port" and rejects out-of-range ports.
// Accepts IPv6 literals in [::1]:853 form via net.SplitHostPort.
func HostPort(s string) error {
	if err := NonEmpty("host:port")(s); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("expected host:port: %w", err)
	}
	if host == "" {
		return fmt.Errorf("expected host:port (empty host)")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q (must be 1–65535)", port)
	}
	return nil
}

// OrDefault returns cur if non-empty, else dflt.
func OrDefault(cur, dflt string) string {
	if cur == "" {
		return dflt
	}
	return cur
}
