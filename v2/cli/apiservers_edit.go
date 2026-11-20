/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Adding one entry to the apiservers: list of a CLI config file, by editing
 * the file's text.
 */
package cli

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Why the file is edited as text, not loaded and written back through viper
// or a YAML library:
//
//   - viper's WriteConfig writes the MERGED configuration. With include: and
//     cli.localconfig in play that would fold the included files and the local
//     overlay into the main file and drop every comment.
//   - A YAML library's round trip keeps comments but normalises the layout of
//     the whole file: every hand-aligned `key:      value` column collapses.
//     Adding one entry would show up as a diff on every line.
//
// So the new entry is spliced into the text, in the style of the entries
// already there, and the result is checked by loading the file again the way
// the CLI will (see AddDaemonConfig). The splice only has to be right about
// the common shape; a layout it does not understand it refuses, and says how to
// add the entry by hand.

// errFlowApiservers is returned for an apiservers: written inline
// (`apiservers: [ ... ]`), which the splice does not edit.
var errFlowApiservers = errors.New("apiservers: is written inline (flow style), which tdns-ncli does not edit")

var (
	reApiserversKey = regexp.MustCompile(`^apiservers:[ \t]*(#.*)?$`)
	reApiserversInl = regexp.MustCompile(`^apiservers:[ \t]*[^ \t#]`)
	reItemStart     = regexp.MustCompile(`^([ \t]*)-([ \t]+)([A-Za-z_-]+):([ \t]*)`)
)

// Layout defaults, taken from cmdv2/cli/tdns-cli.sample.yaml: three-space
// indent, `- name:` and values starting in column 19 of the key.
const (
	defItemIndent = 3
	defDashGap    = 1
	defValueCol   = 19
)

type itemLayout struct {
	indent   int  // spaces before the "-"
	gap      int  // spaces between "-" and the first key
	valueCol int  // distance from the start of a key to its value; 0 = one space
	spaced   bool // entries in the file are separated by blank lines
}

// spliceApiserver returns src with entry added at the end of its apiservers:
// list, and the lines that were added.
//
// If src has no apiservers: key one is appended at the end of the file. If it
// is written inline, errFlowApiservers.
func spliceApiserver(src []byte, e ApiDetails) (out []byte, block string, err error) {
	text := string(src)
	lines := strings.Split(text, "\n")

	start := -1
	for i, l := range lines {
		l = strings.TrimRight(l, "\r")
		if reApiserversKey.MatchString(l) {
			start = i
			break
		}
		if reApiserversInl.MatchString(l) {
			return nil, "", errFlowApiservers
		}
	}

	if start < 0 {
		lay := itemLayout{indent: defItemIndent, gap: defDashGap, valueCol: defValueCol}
		block = renderEntry(e, lay)
		add := "apiservers:\n" + block
		switch {
		case strings.TrimSpace(text) == "":
			return []byte(add), block, nil
		case strings.HasSuffix(text, "\n"):
			return []byte(text + "\n" + add), block, nil
		default:
			return []byte(text + "\n\n" + add), block, nil
		}
	}

	// The block is every following line that is blank, indented, a "- " item
	// at column 0, or a column-0 comment. last is the final line that is
	// really part of it: a column-0 comment after it belongs to what follows.
	last := start
	for j := start + 1; j < len(lines); j++ {
		l := strings.TrimRight(lines[j], "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		if l[0] == ' ' || l[0] == '\t' || isColZeroDash(l) {
			last = j
			continue
		}
		if l[0] == '#' {
			continue
		}
		break
	}

	lay := detectLayout(lines[start+1 : last+1])
	block = renderEntry(e, lay)
	if lay.spaced {
		block = "\n" + block
	}
	insert := strings.Split(strings.TrimSuffix(block, "\n"), "\n")
	merged := make([]string, 0, len(lines)+len(insert))
	merged = append(merged, lines[:last+1]...)
	merged = append(merged, insert...)
	merged = append(merged, lines[last+1:]...)
	return []byte(strings.Join(merged, "\n")), strings.TrimPrefix(block, "\n"), nil
}

func isColZeroDash(l string) bool {
	return l[0] == '-' && (len(l) == 1 || l[1] == ' ' || l[1] == '\t')
}

// detectLayout learns the indentation and alignment of the entries already in
// the block, so the new one looks like its neighbours.
func detectLayout(block []string) itemLayout {
	lay := itemLayout{indent: defItemIndent, gap: defDashGap, valueCol: defValueCol}
	items, seenBlank := 0, false
	for _, l := range block {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			seenBlank = true
			continue
		}
		m := reItemStart.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		items++
		if items == 1 {
			lay.indent = len(strings.ReplaceAll(m[1], "\t", "    "))
			lay.gap = len(strings.ReplaceAll(m[2], "\t", " "))
			switch pad := len(m[4]); {
			case pad >= 2:
				lay.valueCol = len(m[3]) + 1 + pad
			case pad == 1:
				lay.valueCol = 0 // unaligned: one space after every colon
			}
		}
	}
	// Entries are blank-line separated if a blank line sits between items. A
	// single item gives no evidence, so keep the sample's style (separated).
	lay.spaced = items < 2 || seenBlank
	return lay
}

// renderEntry writes e as one "- key: value" list item in the given layout.
func renderEntry(e ApiDetails, lay itemLayout) string {
	type kv struct {
		k, v string
		raw  bool // already YAML (a flow list): written as it stands
	}
	kvs := []kv{{k: "name", v: e.Name}}
	if e.Role != "" {
		kvs = append(kvs, kv{k: "role", v: e.Role})
	}
	kvs = append(kvs, kv{k: "baseurl", v: e.BaseURL})
	// A socket entry has no key: the daemon authenticates the socket by file
	// permissions. An empty apikey: line would only invite filling it in.
	if e.ApiKey != "" {
		kvs = append(kvs, kv{k: "apikey", v: e.ApiKey})
	}
	kvs = append(kvs, kv{k: "authmethod", v: e.AuthMethod})
	if e.TLSAuth != "" {
		kvs = append(kvs, kv{k: "tlsauth", v: e.TLSAuth})
	}
	if len(e.Pins) > 0 {
		q := make([]string, len(e.Pins))
		for i, p := range e.Pins {
			q[i] = `"` + p + `"` // base64: quoted, so a leading + or / reads as text
		}
		kvs = append(kvs, kv{k: "pins", v: "[ " + strings.Join(q, ", ") + " ]", raw: true})
	}
	if e.RootCA != "" {
		kvs = append(kvs, kv{k: "rootca", v: e.RootCA})
	}
	if e.ConfigFile != "" {
		kvs = append(kvs, kv{k: "config-file", v: e.ConfigFile})
	}

	var sb strings.Builder
	for i, p := range kvs {
		if i == 0 {
			sb.WriteString(strings.Repeat(" ", lay.indent) + "-" + strings.Repeat(" ", lay.gap))
		} else {
			sb.WriteString(strings.Repeat(" ", lay.indent+1+lay.gap))
		}
		key := p.k + ":"
		pad := 1
		if lay.valueCol > 0 && lay.valueCol > len(key) {
			pad = lay.valueCol - len(key)
		}
		val := yamlScalar(p.v)
		if p.raw {
			val = p.v
		}
		sb.WriteString(key + strings.Repeat(" ", pad) + val + "\n")
	}
	return sb.String()
}

// reSafeScalar matches values that are plain scalars in YAML as they stand:
// paths, URLs, host names and ordinary tokens. Anything else (an API key with
// a space or a '#' or a leading '*', say) is single-quoted.
var reSafeScalar = regexp.MustCompile(`^[A-Za-z0-9_/.][A-Za-z0-9_/.:@+=\[\]-]*$`)

func yamlScalar(s string) string {
	if reSafeScalar.MatchString(s) && !strings.HasSuffix(s, ":") {
		switch strings.ToLower(s) {
		case "true", "false", "yes", "no", "on", "off", "null", "y", "n":
			// Plain, these would read back as booleans or null.
		default:
			return s
		}
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// writeFileAtomic replaces path with data without a window in which the file
// is half-written, keeping its mode (0600 for a new file: it holds API keys).
// A symlink is followed, so the file it points at is replaced and the link
// stays a link.
//
// The new file belongs to whoever runs this, not necessarily to the old file's
// owner; the CLI config is the invoking operator's own file.
func writeFileAtomic(path string, data []byte) error {
	mode := os.FileMode(0o600)
	target := path
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
		if real, err := filepath.EvalSymlinks(path); err == nil {
			target = real
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".tdns-ncli-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), target)
}
