/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Adding one entry to the apiservers: list of a CLI config file, by editing
 * the file's text.
 */
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
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
	// reBareDash is a list item whose mapping starts on the next line, the
	// dash alone or followed by a comment.
	reBareDash = regexp.MustCompile(`^([ \t]*)-[ \t]*(#.*)?$`)
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
			// A bare "-" with its mapping on the lines below gives the
			// list's indentation (a new item at another indentation does
			// not load), though not the alignment of its keys.
			if b := reBareDash.FindStringSubmatch(l); b != nil {
				items++
				if items == 1 {
					lay.indent = len(strings.ReplaceAll(b[1], "\t", "    "))
				}
			}
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

// yamlScalar writes s as a YAML value that reads back as the string s.
//
// Plain when that is safe, single-quoted otherwise. Safe means the right
// characters AND that YAML reads the plain form as that same string: plain
// 001234 is the octal integer 668, 1e3 is a float and true a boolean, and
// viper hands any of them back as a different string (an API key of 001234
// would come back as "668", and the add would undo itself). The decoder asked
// is the one viper reads the CLI config with, so the two cannot disagree.
func yamlScalar(s string) string {
	if reSafeScalar.MatchString(s) && !strings.HasSuffix(s, ":") {
		switch strings.ToLower(s) {
		case "true", "false", "yes", "no", "on", "off", "null", "y", "n":
			// Plain, these would read back as booleans or null (YAML 1.1
			// readers take all of them; quoting costs nothing).
		default:
			var v interface{}
			if err := yaml.Unmarshal([]byte(s), &v); err == nil {
				if str, ok := v.(string); ok && str == s {
					return s
				}
			}
		}
	}
	// A line break or another character that is not printable does not
	// survive single quotes: a line break folds into a space when read back,
	// and the reader refuses a C1 control (U+0080) outright. Double quotes
	// with escapes do survive, and strconv.Quote escapes exactly the runes
	// that are not printable, with escapes that are YAML's too.
	if strings.IndexFunc(s, func(r rune) bool { return !strconv.IsPrint(r) }) >= 0 {
		return strconv.Quote(s)
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// danglingSymlink returns an error if path is a symbolic link to something
// that does not exist.
//
// Such a path does not stat, so it reads as "no file yet", and writing it by
// renaming a new file over it would replace the link with a plain file: the
// operator's link silently gone, and the file it was meant to point at never
// made. Refuse instead, before anything is written.
func danglingSymlink(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if li, lerr := os.Lstat(path); lerr == nil && li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link to a file that does not exist (%v); create that file, or replace the link, and try again", path, err)
	}
	return nil
}

// writeFileAtomic replaces path with data without a window in which the file
// is half-written, keeping its mode (0600 for a new file: it holds API keys).
// A symlink is followed, so the file it points at is replaced and the link
// stays a link; a link to nothing is refused (see danglingSymlink).
//
// The new file belongs to whoever runs this, not necessarily to the old file's
// owner; the CLI config is the invoking operator's own file. A file a daemon
// reads goes through writeFileAtomicLike instead.
func writeFileAtomic(path string, data []byte) error {
	return replaceFile(path, data, false, nil)
}

// writeFileAtomicLike is writeFileAtomic for a file a daemon reads (the access
// file): the replacement keeps the old file's owner and group, so root editing
// a file the daemon's user owns does not leave one the daemon cannot read. A
// new file takes its mode, owner and group from like (the daemon config), or
// is 0600 and the invoking user's when like is nil.
func writeFileAtomicLike(path string, data []byte, like os.FileInfo) error {
	return replaceFile(path, data, true, like)
}

func replaceFile(path string, data []byte, keepOwner bool, like os.FileInfo) error {
	if err := danglingSymlink(path); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	target := path
	owner := like
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
		owner = fi
		if real, err := filepath.EvalSymlinks(path); err == nil {
			target = real
		}
	} else if like != nil {
		mode = like.Mode().Perm()
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
	if keepOwner && owner != nil {
		if err := chownLike(tmp, owner); err != nil {
			tmp.Close()
			return fmt.Errorf("%s: giving the new file its owner and group: %w", path, err)
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), target)
}

// chownLike gives f the owner and group of like when they differ from f's.
// Nothing to do where the platform has no owners (fileOwner).
func chownLike(f *os.File, like os.FileInfo) error {
	uid, gid, ok := fileOwner(like)
	if !ok {
		return nil
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if cu, cg, ok := fileOwner(fi); ok && cu == uid && cg == gid {
		return nil
	}
	return f.Chown(uid, gid)
}
