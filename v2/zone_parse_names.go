/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The classic zone-file mistake is a name written out in full but without its
// trailing dot. The parser appends the origin to it, so in zone example.test.
//
//	sub.example.test. IN NS ns1.sub.example.test
//
// delegates to ns1.sub.example.test.example.test., a name nobody serves. BIND
// accepts that silently and serves the wrong name, for years if nothing breaks
// loudly enough. The same slip below "$ORIGIN sub.example.test." doubles that
// origin instead: ns1.sub.example.test.sub.example.test.
//
// So a name that ends in the same suffix twice, where that suffix is the zone
// or a name inside it, is refused, owner or RDATA alike. A name that merely
// contains the zone's name somewhere, such as the CDN-style target
// www.example.test.edgekey.net., is not refused: it does not end in the zone,
// so it cannot be a doubled suffix of it.
//
// The check runs on parsed names, where a name written with its trailing dot
// and one completed by the origin look the same. So in zone test. a name such
// as test.test. is refused even when written out in full on purpose. Such
// names are rare; a zone that needs one sets the zone option
// allow-doubled-suffix, which turns the check off for that zone.

// One refusal lists every such record, up to doubledSuffixListLimit, so the
// operator fixes them all from one error rather than one per reload. The
// parser does not say which file or line a record came from, so each entry
// quotes the record and the name as it most likely appears in the file -- the
// name written out in full, without its trailing dot -- which a search of the
// zone file and its includes finds.

// doubledSuffixListLimit bounds how many records one refusal lists.
const doubledSuffixListLimit = 20

// DoubledSuffixReport collects the records of a zone whose names end in a
// doubled suffix of the zone, for one refusal that lists them all.
type DoubledSuffixReport struct {
	zoneLabels []string
	lines      []string
	total      int
}

// NewDoubledSuffixReport starts a report for zone. The root zone has no
// suffix to double, so its report never finds anything.
func NewDoubledSuffixReport(zone string) *DoubledSuffixReport {
	return &DoubledSuffixReport{zoneLabels: dns.SplitDomainName(dns.Fqdn(zone))}
}

// Check reports whether one of rr's names -- its owner, then each domain name
// in its RDATA -- ends in a doubled suffix of the zone, and records the first
// such name.
func (r *DoubledSuffixReport) Check(rr dns.RR) bool {
	if r == nil || rr == nil || len(r.zoneLabels) == 0 {
		return false
	}
	for _, name := range append([]string{rr.Header().Name}, rdataDomainNames(rr)...) {
		suffix, ok := doubledZoneSuffix(r.zoneLabels, name)
		if !ok {
			continue
		}
		r.total++
		if len(r.lines) < doubledSuffixListLimit {
			r.lines = append(r.lines, fmt.Sprintf("%q ends in %q twice: look for %q without a trailing dot (record: %s)",
				name, suffix, asWritten(name, suffix), rr.String()))
		}
		return true
	}
	return false
}

// Err returns the refusal listing what Check found, or nil when it found
// nothing.
func (r *DoubledSuffixReport) Err() error {
	if r == nil || r.total == 0 {
		return nil
	}
	var b strings.Builder
	what := "a name ends"
	if r.total > 1 {
		what = fmt.Sprintf("%d names end", r.total)
	}
	fmt.Fprintf(&b, "%s in a suffix twice, so a trailing dot is probably missing; if a name is meant, set the zone option allow-doubled-suffix", what)
	for _, line := range r.lines {
		b.WriteString("\n  ")
		b.WriteString(line)
	}
	if more := r.total - len(r.lines); more > 0 {
		fmt.Fprintf(&b, "\n  and %d more", more)
	}
	return errors.New(b.String())
}

// CheckDoubledZoneSuffix returns the refusal for rr alone, or nil.
func CheckDoubledZoneSuffix(zone string, rr dns.RR) error {
	r := NewDoubledSuffixReport(zone)
	r.Check(rr)
	return r.Err()
}

// asWritten is how a doubled name most likely appears in the zone file: one
// copy of the suffix fewer, without the trailing dot whose absence let the
// origin double it. suffix comes from name's own labels, so it is a literal
// suffix of it.
func asWritten(name, suffix string) string {
	return strings.TrimSuffix(strings.TrimSuffix(dns.Fqdn(name), suffix), ".")
}

// doubledZoneSuffix reports whether name ends in the same run of labels twice,
// where that run is the zone (zoneLabels) or a name below it, and returns the
// doubled suffix. Labels compare case-insensitively.
func doubledZoneSuffix(zoneLabels []string, name string) (string, bool) {
	labels := dns.SplitDomainName(dns.Fqdn(name))
	n, zl := len(labels), len(zoneLabels)
	if zl == 0 || n < 2*zl {
		return "", false
	}
	// Labels are compared as DNS compares them, folding A-Z only
	// (core.EqualNames). strings.EqualFold folds Unicode as well, and would
	// read a label holding U+017F (long s) as one holding "s".
	for i := 0; i < zl; i++ {
		if !core.EqualNames(labels[n-zl+i], zoneLabels[i]) {
			return "", false // not in the zone at all
		}
	}
	for k := zl; 2*k <= n; k++ {
		doubled := true
		for i := 0; i < k; i++ {
			if !core.EqualNames(labels[n-k+i], labels[n-2*k+i]) {
				doubled = false
				break
			}
		}
		if doubled {
			return strings.Join(labels[n-k:], ".") + ".", true
		}
	}
	return "", false
}

// rdataDomainNames returns the domain names in rr's RDATA: every string (or
// []string) field the dns package tags as a domain name, in embedded structs
// too (CDS embeds DS, HTTPS embeds SVCB). The header is not RDATA and is left
// out; the owner is checked on its own.
func rdataDomainNames(rr dns.RR) []string {
	v := reflect.ValueOf(rr)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for _, idx := range domainNameFields(v.Type()) {
		f := v.FieldByIndex(idx)
		switch f.Kind() {
		case reflect.String:
			out = append(out, f.String())
		case reflect.Slice:
			for j := 0; j < f.Len(); j++ {
				out = append(out, f.Index(j).String())
			}
		}
	}
	return out
}

// domainNameFieldCache maps an RR struct type to the index paths of its domain
// name fields, so a large zone pays for the reflection walk once per type, not
// once per record.
var domainNameFieldCache sync.Map // reflect.Type -> [][]int

var rrHeaderType = reflect.TypeOf(dns.RR_Header{})

func domainNameFields(t reflect.Type) [][]int {
	if cached, ok := domainNameFieldCache.Load(t); ok {
		return cached.([][]int)
	}
	var paths [][]int
	var walk func(t reflect.Type, prefix []int)
	walk = func(t reflect.Type, prefix []int) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Type == rrHeaderType {
				continue
			}
			path := append(append([]int(nil), prefix...), i)
			if f.Anonymous && f.Type.Kind() == reflect.Struct {
				walk(f.Type, path)
				continue
			}
			switch f.Tag.Get("dns") {
			case "domain-name", "cdomain-name":
			default:
				continue
			}
			if f.Type.Kind() == reflect.String ||
				(f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.String) {
				paths = append(paths, path)
			}
		}
	}
	walk(t, nil)
	domainNameFieldCache.Store(t, paths)
	return paths
}
