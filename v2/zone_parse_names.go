/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"reflect"
	"strings"
	"sync"

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

// CheckDoubledZoneSuffix returns an error naming the first name in rr -- its
// owner, then each domain name in its RDATA -- that ends in a doubled suffix of
// zone.
func CheckDoubledZoneSuffix(zone string, rr dns.RR) error {
	if rr == nil {
		return nil
	}
	zone = dns.Fqdn(zone)
	zoneLabels := dns.SplitDomainName(zone)
	if len(zoneLabels) == 0 {
		return nil // the root zone: no suffix to double
	}
	check := func(name string) error {
		if suffix, ok := doubledZoneSuffix(zoneLabels, name); ok {
			return fmt.Errorf("%q ends in %q twice; a trailing dot is probably missing (record: %s; if the name is meant, set the zone option allow-doubled-suffix)",
				name, suffix, rr.String())
		}
		return nil
	}
	if err := check(rr.Header().Name); err != nil {
		return err
	}
	for _, name := range rdataDomainNames(rr) {
		if err := check(name); err != nil {
			return err
		}
	}
	return nil
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
	for i := 0; i < zl; i++ {
		if !strings.EqualFold(labels[n-zl+i], zoneLabels[i]) {
			return "", false // not in the zone at all
		}
	}
	for k := zl; 2*k <= n; k++ {
		doubled := true
		for i := 0; i < k; i++ {
			if !strings.EqualFold(labels[n-k+i], labels[n-2*k+i]) {
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
