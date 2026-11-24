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

	start, err := findApiserversKey(lines)
	if err != nil {
		return nil, "", err
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

	last := apiserversBlockEnd(lines, start)
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

// apiserversBlockEnd returns the last line of the apiservers: block whose key
// is on line start. The block is every following line that is blank,
// indented, a "- " item at column 0, or a column-0 comment; the last line
// really part of it is the last that is not blank or such a comment, which
// belongs to what follows.
func apiserversBlockEnd(lines []string, start int) int {
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
	return last
}

// findApiserversKey returns the line of the apiservers: key in lines, -1 if
// there is none, or errFlowApiservers.
func findApiserversKey(lines []string) (int, error) {
	for i, l := range lines {
		l = strings.TrimRight(l, "\r")
		if reApiserversKey.MatchString(l) {
			return i, nil
		}
		if reApiserversInl.MatchString(l) {
			return -1, errFlowApiservers
		}
	}
	return -1, nil
}

// reKeyLine is a "key: rest" line of a mapping, the indentation removed.
var reKeyLine = regexp.MustCompile(`^([A-Za-z_-]+):(.*)$`)

// entryEdit says what editEntryText changes in an apiservers: item.
type entryEdit struct {
	// repin: verify the daemon by pin. The item's tlsauth:, pins: and rootca:
	// lines go, and "tlsauth: pin" and the new entry's pins are added.
	repin bool
	// toCert: authenticate with the client certificate. The item's apikey:
	// line goes, and its authmethod: becomes certificate where it stands (or
	// is added, if it has none).
	toCert bool
	// bindTo: the daemon config the item names from now on, its
	// config-file: line (added; one it has goes). For a key entry found by
	// its address alone, switched to the certificate enrolled on that
	// daemon.
	bindTo string
}

// reAuthMethodValue splits the rest of an "authmethod:" line into the space
// before the value and any comment after it.
var reAuthMethodValue = regexp.MustCompile(`^([ \t]*)[^#]*?([ \t]+#.*)?$`)

// repinEntryText is editEntryText making the item verify by pin, and nothing
// else.
func repinEntryText(src []byte, name string, up ApiDetails) ([]byte, error) {
	return editEntryText(src, name, up, entryEdit{repin: true})
}

// editEntryText returns src with the apiservers: item named name changed as
// ed says: the lines of the keys it replaces removed, each with any lines of
// its value below it, an authmethod: line given its new value in place, and
// the new lines (tlsauth: and pins:, or authmethod: if the item had none)
// added at the end of the item, aligned like the list's first item. Nothing
// else in the file changes, comments and alignment included. An item it
// cannot edit with confidence (tabs, one of those keys on the item's first
// line) it refuses. The caller checks the result by loading it.
func editEntryText(src []byte, name string, up ApiDetails, ed entryEdit) ([]byte, error) {
	drops := map[string]bool{}
	if ed.repin {
		drops["tlsauth"], drops["pins"], drops["rootca"] = true, true, true
	}
	if ed.toCert {
		drops["apikey"] = true
	}
	if ed.bindTo != "" {
		drops["config-file"] = true
	}
	lines := strings.Split(string(src), "\n")
	start, err := findApiserversKey(lines)
	if err != nil {
		return nil, err
	}
	if start < 0 {
		return nil, errors.New("it has no apiservers: list")
	}
	last := apiserversBlockEnd(lines, start)

	// The items: each from its "-" line at the list's indentation to the
	// next one. A "-" deeper in starts a nested list, not an item.
	type item struct{ from, to int }
	var items []item
	listIndent := -1
	for j := start + 1; j <= last; j++ {
		l := strings.TrimRight(lines[j], "\r")
		var ind string
		if m := reItemStart.FindStringSubmatch(l); m != nil {
			ind = m[1]
		} else if b := reBareDash.FindStringSubmatch(l); b != nil {
			ind = b[1]
		} else {
			continue
		}
		if strings.Contains(ind, "\t") {
			return nil, errors.New("the apiservers: list is indented with tabs")
		}
		if listIndent < 0 {
			listIndent = len(ind)
		}
		if len(ind) != listIndent {
			continue
		}
		if n := len(items); n > 0 {
			items[n-1].to = j
		}
		items = append(items, item{from: j, to: last + 1})
	}

	found := -1
	for k, it := range items {
		var v []map[string]interface{}
		if err := yaml.Unmarshal([]byte(dedentLines(lines[it.from:it.to], listIndent)), &v); err != nil || len(v) != 1 {
			continue
		}
		if n, ok := v[0]["name"].(string); ok && n == name {
			if found >= 0 {
				return nil, fmt.Errorf("two entries in it are named %q", name)
			}
			found = k
		}
	}
	if found < 0 {
		return nil, fmt.Errorf("no entry named %q is in it", name)
	}
	it := items[found]

	// The item's keys start in keyCol: after "- " on its first line, or, for a
	// "-" alone on its line, where its first key below starts.
	keyCol := -1
	if m := reItemStart.FindStringSubmatch(strings.TrimRight(lines[it.from], "\r")); m != nil {
		if strings.Contains(m[2], "\t") {
			return nil, errors.New("the entry is indented with tabs")
		}
		if k := strings.ToLower(m[3]); drops[k] || (ed.toCert && k == "authmethod") {
			return nil, fmt.Errorf("its %s: is on its first line", m[3])
		}
		keyCol = len(m[1]) + 1 + len(m[2])
	}

	kept := []string{lines[it.from]}
	lastContent := 0 // index in kept of the item's last line of content
	dropping := false
	hasAuthMethod := false
	for j := it.from + 1; j < it.to; j++ {
		l := strings.TrimRight(lines[j], "\r")
		body := strings.TrimLeft(l, " ")
		ind := len(l) - len(body)
		if strings.TrimSpace(l) == "" || strings.HasPrefix(body, "#") {
			kept = append(kept, lines[j]) // blank lines and comments stay
			if ind > listIndent && strings.TrimSpace(l) != "" {
				lastContent = len(kept) - 1
			}
			continue
		}
		if strings.HasPrefix(body, "\t") {
			return nil, errors.New("the entry is indented with tabs")
		}
		if keyCol < 0 {
			keyCol = ind
		}
		// Lines deeper than the keys, or a "-" at their column, after a
		// removed key are its value: they go with it.
		if dropping && (ind > keyCol || (ind == keyCol && strings.HasPrefix(body, "-"))) {
			continue
		}
		dropping = false
		line := lines[j]
		if m := reKeyLine.FindStringSubmatch(body); m != nil && ind == keyCol {
			k := strings.ToLower(m[1])
			if drops[k] {
				dropping = true
				continue
			}
			if ed.toCert && k == "authmethod" {
				// The value replaced where it stands, its spacing and any
				// comment kept. A value on the lines below would be a
				// multi-line scalar nobody writes for this key: refused.
				hasAuthMethod = true
				v := reAuthMethodValue.FindStringSubmatch(m[2])
				if v == nil || strings.TrimSpace(strings.TrimSuffix(m[2], v[2])) == "" {
					return nil, errors.New("its authmethod: has no value on its line")
				}
				pad := v[1]
				if pad == "" {
					pad = " "
				}
				line = l[:ind] + m[1] + ":" + pad + "certificate" + v[2]
				if strings.HasSuffix(lines[j], "\r") {
					line += "\r"
				}
			}
		}
		kept = append(kept, line)
		lastContent = len(kept) - 1
	}
	if keyCol < 0 {
		return nil, errors.New("the entry has no keys")
	}

	valueCol := detectLayout(lines[start+1 : last+1]).valueCol
	var add []string
	if ed.toCert && !hasAuthMethod {
		add = append(add, kvLine(keyCol, valueCol, "authmethod", "certificate"))
	}
	if ed.repin {
		add = append(add,
			kvLine(keyCol, valueCol, "tlsauth", "pin"),
			kvLine(keyCol, valueCol, "pins", pinsFlow(up.Pins)))
	}
	if ed.bindTo != "" {
		add = append(add, kvLine(keyCol, valueCol, "config-file", yamlScalar(ed.bindTo)))
	}
	edited := make([]string, 0, len(kept)+len(add))
	edited = append(edited, kept[:lastContent+1]...)
	edited = append(edited, add...)
	edited = append(edited, kept[lastContent+1:]...)

	out := make([]string, 0, len(lines)+len(add))
	out = append(out, lines[:it.from]...)
	out = append(out, edited...)
	out = append(out, lines[it.to:]...)
	return []byte(strings.Join(out, "\n")), nil
}

// dedentLines joins lines, each with up to n leading spaces removed.
func dedentLines(lines []string, n int) string {
	var sb strings.Builder
	for _, l := range lines {
		l = strings.TrimRight(l, "\r")
		k := 0
		for k < n && k < len(l) && l[k] == ' ' {
			k++
		}
		sb.WriteString(l[k:] + "\n")
	}
	return sb.String()
}

// kvLine is one "key: value" line with the key in column col and, when
// valueCol says so, the value aligned (valueCol counts from the key's start;
// 0 is one space after the colon). The value is written as it stands.
func kvLine(col, valueCol int, key, val string) string {
	key += ":"
	pad := 1
	if valueCol > len(key) {
		pad = valueCol - len(key)
	}
	return strings.Repeat(" ", col) + key + strings.Repeat(" ", pad) + val
}

// pinsFlow writes pins as a YAML flow list, each double-quoted: base64, so a
// leading + or / reads as text, and escaped (strconv.Quote, whose escapes are
// YAML's too), so a pin read from a hand-written file with a quote or a
// backslash in it reads back as itself.
func pinsFlow(pins []string) string {
	q := make([]string, len(pins))
	for i, p := range pins {
		q[i] = strconv.Quote(p)
	}
	return "[ " + strings.Join(q, ", ") + " ]"
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
	// No baseurl for a daemon with only the local admin socket, which
	// tdns-ncli finds through config-file:.
	if e.BaseURL != "" {
		kvs = append(kvs, kv{k: "baseurl", v: e.BaseURL})
	}
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
		kvs = append(kvs, kv{k: "pins", v: pinsFlow(e.Pins), raw: true})
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
