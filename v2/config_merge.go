/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Merging an include:d config file into the one that included it.
 *
 * The default is what it has always been: the included file replaces. Merging
 * happens only for an include that asked for it, and even then only for the
 * paths on the allowlist below.
 *
 * Design note in docs/2026-08-27-config-include-merge.md. The short version of
 * why merging is not simply the default: the failure being fixed ("I included
 * a file that contributes zones and lost the ones I had") and the failure
 * default-on would introduce ("I upgraded and started serving zones that were
 * being clobbered on purpose") are opposites, and only the second arrives
 * unattended -- processConfigFile is reached from four runtime reload paths,
 * one of them the SIGHUP watcher.
 */

package tdns

import (
	"fmt"
	"sort"
	"strings"
)

// mergeStrategy is how one allowlisted path combines two files' contributions.
//
// Three strategies rather than one because these are three kinds of thing. A
// collection of named objects cannot be deep-merged -- combining two
// definitions of one zone produces a zone neither file describes -- while a
// set genuinely is the same fact stated twice.
type mergeStrategy int

const (
	// concatNamed: a list of maps each carrying a "name". Concatenate;
	// a repeated name is a collision.
	concatNamed mergeStrategy = iota
	// unionStrings: a list of strings with set semantics.
	unionStrings
	// mergeNamedMap: a map keyed by object name. Merge by key; a key in both
	// is a collision.
	mergeNamedMap
	// mergeMapOfStringLists: a map whose values are string lists. Merge by
	// key, union the leaves.
	mergeMapOfStringLists
)

// mergeAllowlist is the whole of what an opted-in include may combine.
// Everything else replaces, opted in or not.
//
// Deliberately absent: listeners.addresses, apiserver.addresses,
// listeners.transports. Concatenating those would silently make a server
// listen on more addresses than the file in front of you says -- the same
// class of failure as widening an ACL, and worse than the clobber this is
// fixing, because a clobber is at least visible in what the server runs.
//
// dnssec.templates (policy templates) and keys.tsig are the same shape as
// entries here and are deliberately left off until something needs them.
var mergeAllowlist = map[string]mergeStrategy{
	"zones":                   concatNamed,
	"templates":               concatNamed,
	"dnssec.policies":         mergeNamedMap,
	"dnssec.large-algorithms": unionStrings,
	"dnssec.split-algorithms": mergeMapOfStringLists,
}

// isAllowlistPrefix reports whether any allowlisted path lives strictly below
// this one, i.e. whether recursing is needed to reach one.
func isAllowlistPrefix(path string) bool {
	for k := range mergeAllowlist {
		if strings.HasPrefix(k, path+".") {
			return true
		}
	}
	return false
}

// nameCollision records one allowlisted item defined in two files.
//
// It carries both file paths because that is the useful half of "X is defined
// twice", and it is the half the merge would otherwise discard: once two maps
// are combined, nothing remembers which file each key came from.
type nameCollision struct {
	Path  string // allowlisted path, e.g. "zones"
	Name  string // the item's name
	First string // file the first definition came from
	Again string // file the second came from
}

func (c nameCollision) Error() string {
	return fmt.Sprintf("%s: %q is defined in both %s and %s", c.Path, c.Name, c.First, c.Again)
}

// clobber records a replace that discarded a non-empty allowlisted key.
//
// The replace still happens -- this is the WARN that makes it visible. Without
// it, opt-in would leave the original complaint unaddressed for everyone who
// does not opt in: they would still lose their zones, still silently.
type clobber struct {
	Path string
	By   string // the file that replaced it
	Lost int    // how many items were dropped, where countable
}

// mergeFindings is what a whole load accumulates, shared down the recursion.
type mergeFindings struct {
	Collisions []nameCollision
	Clobbers   []clobber
}

// mergeState is per CONFIG MAP, not per load, and that distinction is the
// whole of N7.
//
// A shared first-wins origin map cannot express what a collision needs: two
// definitions of one name have two different origins, and one map keyed by
// name can only hold one. With per-map origins, a child returns the origins of
// ITS items -- ultimately the leaf file each was read from -- and the parent
// compares its own against the child's. Merge them into one shared map and a
// nested include gets blamed on the intermediate file that merged it, which is
// precisely the wrong half of "X is defined in A and B".
type mergeState struct {
	origin   map[string]string // "<path>\x00<name>" -> file the item was READ from
	findings *mergeFindings    // shared across the load
}

func newMergeState() *mergeState {
	return &mergeState{origin: map[string]string{}, findings: &mergeFindings{}}
}

// forChild returns a state for a nested config map, sharing the findings but
// starting a fresh origin map so the child records its own provenance.
func (m *mergeState) forChild() *mergeState {
	return &mergeState{origin: map[string]string{}, findings: m.findings}
}

// Collisions and Clobbers read through to the shared findings.
func (m *mergeState) Collisions() []nameCollision { return m.findings.Collisions }
func (m *mergeState) Clobbers() []clobber         { return m.findings.Clobbers }

// adopt takes over the origins of a map that has been merged into this one,
// for items this state does not already know. Not overwriting is what keeps
// the FIRST definition first.
func (m *mergeState) adopt(child *mergeState) {
	for k, v := range child.origin {
		if _, have := m.origin[k]; !have {
			m.origin[k] = v
		}
	}
}

// originFrom reports where an incoming item came from, preferring the source
// map own record (the leaf) over the file that happens to be merging it.
func originFrom(src *mergeState, path, name, fallback string) string {
	if src != nil {
		if f, ok := src.origin[originKey(path, name)]; ok {
			return f
		}
	}
	return fallback
}

func originKey(path, name string) string { return path + "\x00" + name }

// collationKey is the name two contributions are compared under to decide
// whether they are the same item. Each collection is compared the way the
// DAEMON keys it, and they are not keyed alike.
//
// Zones fold: zoneNameKey is FQDN-normalized and case-folded, because zone
// names are DNS names and RFC 4343 makes two spellings one zone. Without it the
// merge and the ParseZones pre-pass disagree -- "example.com" from one file and
// "example.com." from another are one zone to the daemon and get quarantined,
// but comparing raw YAML strings here saw two items and never logged which two
// files they came from, so the operator is told the zone is broken and not told
// where either half lives.
//
// Templates and policies do NOT fold. They are map keys, not DNS names:
// buildTemplateMap does Templates[tmpl.Name] and every lookup matches exactly,
// so `Foo` and `foo` are two distinct templates that both load. Folding them
// here would report a collision the daemon does not have -- and for
// dnssec.policies the collision path DELETES the name, so it would remove a
// policy the daemon would have kept. config check reached the same conclusion
// for template names and warns rather than failing on a case-differing pair.
func collationKey(path, name string) string {
	if path == "zones" {
		return zoneNameKey(name)
	}
	return name
}

// noteOrigin records where an item came from, returning the earlier file and
// true if this name has been seen before.
func (m *mergeState) noteOrigin(path, name, file string) (string, bool) {
	k := originKey(path, name)
	if prev, seen := m.origin[k]; seen {
		return prev, true
	}
	m.origin[k] = file
	return "", false
}

// OriginOf reports the file an allowlisted item was read from.
func (m *mergeState) OriginOf(path, name string) (string, bool) {
	f, ok := m.origin[originKey(path, name)]
	return f, ok
}

// mergeConfigMaps folds src (from srcFile) into dst.
//
// doMerge is the include's own opt-in. When false this behaves exactly as the
// loader always has -- one level of map merge, replace for everything else --
// with the single addition that replacing a non-empty allowlisted key is
// recorded as a clobber.
//
// prefix is the dotted path of dst within the config, so nested allowlisted
// paths resolve. That matters more than it looks: dnssec.policies is NOT a
// top-level key. In the pre-existing merge, "dnssec" takes the map branch and
// "policies" is assigned by the inner loop -- so a dispatcher hooked only to
// top-level keys would compile, pass most tests, and leave the motivating case
// still replacing.
func mergeConfigMaps(dst, src map[string]interface{}, prefix, srcFile string,
	doMerge bool, st *mergeState, srcState *mergeState) error {

	for _, k := range sortedStringKeys(src) {
		v := src[k]
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}

		strategy, allowlisted := mergeAllowlist[path]
		existing, exists := dst[k]

		switch {
		case allowlisted && doMerge && exists:
			merged, err := applyStrategy(strategy, path, existing, v, srcFile, st, srcState)
			if err != nil {
				return err
			}
			dst[k] = merged

		case allowlisted && !doMerge && exists && !isEmptyValue(existing):
			// The replace still happens; it just stops being silent.
			st.findings.Clobbers = append(st.findings.Clobbers, clobber{
				Path: path, By: srcFile, Lost: countItems(existing),
			})
			recordOrigins(path, v, srcFile, st, srcState, true)
			dst[k] = v

		case exists:
			dstMap, ok1 := existing.(map[string]interface{})
			srcMap, ok2 := v.(map[string]interface{})
			// Recurse ONLY as far as the historical merge went, plus whatever
			// is needed to reach a nested allowlisted key.
			//
			// The loader has always merged exactly one level: two top-level
			// maps have their children assigned wholesale into the destination.
			// Recursing unconditionally -- which an earlier version of this did
			// -- deep-merges every nested map instead, so an include carrying a
			// partial dnssec.kasp stopped dropping the siblings it omits. That
			// is a silent change to what a BARE-STRING include does, on the
			// default path this whole opt-in design exists to leave alone, and
			// it is live on every SIGHUP.
			//
			// prefix == "" reproduces that one level. isAllowlistPrefix carries
			// the recursion further only where an allowlisted path actually
			// lives below (today: dnssec, for dnssec.policies and friends).
			if ok1 && ok2 && (prefix == "" || isAllowlistPrefix(path)) {
				if err := mergeConfigMaps(dstMap, srcMap, path, srcFile, doMerge, st, srcState); err != nil {
					return err
				}
				continue
			}
			if allowlisted {
				recordOrigins(path, v, srcFile, st, srcState, true)
			}
			dst[k] = v

		default:
			if allowlisted {
				recordOrigins(path, v, srcFile, st, srcState, false)
			}
			dst[k] = v
		}
	}
	return nil
}

// applyStrategy combines one allowlisted path's two contributions.
func applyStrategy(s mergeStrategy, path string, dstVal, srcVal interface{},
	srcFile string, st *mergeState, srcState *mergeState) (interface{}, error) {

	switch s {
	case concatNamed:
		dstList, ok1 := dstVal.([]interface{})
		srcList, ok2 := srcVal.([]interface{})
		if !ok1 || !ok2 {
			return nil, typeMismatch(path, dstVal, srcVal, "a list")
		}
		for _, item := range srcList {
			name := itemName(item)
			if name == "" {
				continue
			}
			key := collationKey(path, name)
			// The item's own origin, not the file that happens to be merging
			// it: with a nested include those differ, and the leaf is the one
			// worth naming.
			from := originFrom(srcState, path, key, srcFile)
			if first, dup := st.noteOrigin(path, key, from); dup {
				st.findings.Collisions = append(st.findings.Collisions, nameCollision{
					Path: path, Name: name, First: first, Again: from,
				})
			}
		}
		return append(dstList, srcList...), nil

	case unionStrings:
		dstList, ok1 := dstVal.([]interface{})
		srcList, ok2 := srcVal.([]interface{})
		if !ok1 || !ok2 {
			return nil, typeMismatch(path, dstVal, srcVal, "a list")
		}
		seen := map[string]bool{}
		out := make([]interface{}, 0, len(dstList)+len(srcList))
		for _, item := range append(append([]interface{}{}, dstList...), srcList...) {
			s := fmt.Sprint(item)
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, item)
		}
		return out, nil

	case mergeNamedMap:
		dstMap, ok1 := dstVal.(map[string]interface{})
		srcMap, ok2 := srcVal.(map[string]interface{})
		if !ok1 || !ok2 {
			return nil, typeMismatch(path, dstVal, srcVal, "a mapping")
		}
		for _, name := range sortedStringKeys(srcMap) {
			if _, clash := dstMap[name]; clash {
				first, _ := st.OriginOf(path, name)
				st.findings.Collisions = append(st.findings.Collisions, nameCollision{
					Path: path, Name: name, First: first,
					Again: originFrom(srcState, path, name, srcFile),
				})
				// NEITHER definition wins: the first is removed too. Picking
				// one arbitrarily is how a zone ends up signed by a policy
				// nobody wrote down. Deleting it also gives the right
				// downstream behaviour for free -- a zone naming the policy
				// now fails to resolve it and is quarantined by the existing
				// unusable-policy path, while every other zone keeps serving.
				delete(dstMap, name)
				continue
			}
			key := collationKey(path, name)
			st.noteOrigin(path, key, originFrom(srcState, path, key, srcFile))
			dstMap[name] = srcMap[name]
		}
		return dstMap, nil

	case mergeMapOfStringLists:
		dstMap, ok1 := dstVal.(map[string]interface{})
		srcMap, ok2 := srcVal.(map[string]interface{})
		if !ok1 || !ok2 {
			return nil, typeMismatch(path, dstVal, srcVal, "a mapping")
		}
		for _, key := range sortedStringKeys(srcMap) {
			existing, have := dstMap[key]
			if !have {
				dstMap[key] = srcMap[key]
				continue
			}
			// Union the leaves. This WIDENS what the server will accept --
			// for split-algorithms, which KSK/ZSK pairings are permitted --
			// so it is a widening, not a restatement. Bounded: it only gates
			// policy parse, and only for an include that opted in.
			merged, err := applyStrategy(unionStrings, path+"."+key, existing, srcMap[key], srcFile, st, srcState)
			if err != nil {
				return nil, err
			}
			dstMap[key] = merged
		}
		return dstMap, nil
	}
	return nil, fmt.Errorf("%s: unknown merge strategy", path)
}

// typeMismatch is a hard error rather than a silent fall back to replace: two
// files disagreeing about whether zones: is a list or a mapping is a mistake,
// and quietly picking one of them is how it survives to production.
func typeMismatch(path string, dstVal, srcVal interface{}, want string) error {
	return fmt.Errorf("%s: cannot merge %T with %T; both must be %s", path, dstVal, srcVal, want)
}

// recordOrigins notes provenance for a whole allowlisted value at once, used
// when the value is assigned rather than merged. replaced says the value
// displaced an earlier one, in which case earlier origins for this path are
// dropped -- they refer to items that are no longer in the config.
// recordOrigins notes where each allowlisted item came from.
//
// srcState is the child's own origin map, consulted per item: with a nested
// include the file doing the merging and the file the item was READ from are
// different, and the leaf is the one worth naming. Stamping srcFile instead --
// which this did on the assign paths -- blames the intermediate file whenever
// the destination did not already carry the key, which is the common shape of
// a main config that delegates a whole section to an include.
func recordOrigins(path string, v interface{}, srcFile string, st, srcState *mergeState, replaced bool) {
	if replaced {
		for k := range st.origin {
			if strings.HasPrefix(k, path+"\x00") {
				delete(st.origin, k)
			}
		}
	}
	switch val := v.(type) {
	case []interface{}:
		for _, item := range val {
			if name := itemName(item); name != "" {
				key := collationKey(path, name)
				st.noteOrigin(path, key, originFrom(srcState, path, key, srcFile))
			}
		}
	case map[string]interface{}:
		for name := range val {
			st.noteOrigin(path, collationKey(path, name), srcFile)
		}
	}
}

// itemName pulls the "name" out of one entry of a named collection.
func itemName(item interface{}) string {
	m, ok := item.(map[string]interface{})
	if !ok {
		return ""
	}
	for _, k := range []string{"name", "Name"} {
		if n, ok := m[k].(string); ok {
			return n
		}
	}
	return ""
}

func countItems(v interface{}) int {
	switch val := v.(type) {
	case []interface{}:
		return len(val)
	case map[string]interface{}:
		return len(val)
	}
	return 0
}

func isEmptyValue(v interface{}) bool {
	if v == nil {
		return true
	}
	return countItems(v) == 0
}

func sortedStringKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// includeEntry is one entry of the include: list.
//
// A bare string is the historical form and still means replace. The map form
// is the only way to ask for merging, so every config written before this
// existed keeps its exact behaviour.
type includeEntry struct {
	File  string
	Merge bool
}

// parseIncludeEntry accepts "file.yaml" or {file: file.yaml, merge: true}.
//
// Anything else is an error rather than a skip. Today a non-string entry is
// silently ignored (the type assertion simply fails), which means a mistyped
// include does nothing and says nothing. Since this work gives the map form
// meaning, the quiet skip has to go with it.
func parseIncludeEntry(inc interface{}) (includeEntry, error) {
	switch v := inc.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return includeEntry{}, fmt.Errorf("empty include entry")
		}
		return includeEntry{File: v}, nil

	case map[string]interface{}:
		e := includeEntry{}
		for _, k := range sortedStringKeys(v) {
			switch k {
			case "file":
				f, ok := v[k].(string)
				if !ok || strings.TrimSpace(f) == "" {
					return includeEntry{}, fmt.Errorf("include: file must be a non-empty string")
				}
				e.File = f
			case "merge":
				m, ok := v[k].(bool)
				if !ok {
					return includeEntry{}, fmt.Errorf("include %q: merge must be true or false", e.File)
				}
				e.Merge = m
			default:
				return includeEntry{}, fmt.Errorf("include: unknown key %q (expected file, merge)", k)
			}
		}
		if e.File == "" {
			return includeEntry{}, fmt.Errorf("include: an entry has no file")
		}
		return e, nil
	}
	return includeEntry{}, fmt.Errorf("include: entry must be a path or {file, merge}, got %T", inc)
}

// lookupPath walks a dotted path into a raw config map.
func lookupPath(m map[string]interface{}, path string) (interface{}, bool) {
	cur := interface{}(m)
	for _, part := range strings.Split(path, ".") {
		asMap, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = asMap[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// report logs what the load found, once, at the top of the recursion.
//
// A clobber is a WARN and not an error: replacing is still legal and still
// what happens. Saying so is what keeps opt-in from leaving the original
// complaint unaddressed for operators who never opt in -- they lose zones
// exactly as before, but no longer silently, and the message names the remedy.
func (m *mergeState) report(mainFile string) {
	for _, c := range m.findings.Clobbers {
		lgConfig.Warn("include replaced a config section rather than adding to it",
			"config", mainFile, "key", c.Path, "replaced-by", c.By, "entries-dropped", c.Lost,
			"hint", "this is the historical behaviour; use `- {file: "+c.By+", merge: true}` to combine instead")
	}
	for _, c := range m.findings.Collisions {
		lgConfig.Error("config item defined twice; neither definition is used",
			"config", mainFile, "key", c.Path, "name", c.Name, "first", c.First, "again", c.Again)
	}
}
