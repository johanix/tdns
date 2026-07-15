/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package options

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParseBufsizeFlag(t *testing.T) {
	if val, ok := ParseBufsizeFlag("+BUFsize=512"); !ok || val != "512" {
		t.Fatalf("+BUFsize=512: val=%q ok=%v", val, ok)
	}
	if val, ok := ParseBufsizeFlag("+BUFSIZ=1232"); !ok || val != "1232" {
		t.Fatalf("+BUFSIZ=1232: val=%q ok=%v", val, ok)
	}
	if _, ok := ParseBufsizeFlag("+DO"); ok {
		t.Fatal("+DO should not match bufsize")
	}
}

func TestParseEDNSUDPSize(t *testing.T) {
	size, err := ParseEDNSUDPSize("512")
	if err != nil || size != 512 {
		t.Fatalf("512: size=%d err=%v", size, err)
	}
	size, err = ParseEDNSUDPSize("300")
	if err != nil || size != dns.MinMsgSize {
		t.Fatalf("300: size=%d err=%v, want %d", size, err, dns.MinMsgSize)
	}
	if _, err := ParseEDNSUDPSize("abc"); err == nil {
		t.Fatal("expected error for abc")
	}
	if _, err := ParseEDNSUDPSize("70000"); err == nil {
		t.Fatal("expected error for 70000")
	}
}

func TestEDNSUDPSizeFromMap(t *testing.T) {
	size, err := EDNSUDPSizeFromMap(nil)
	if err != nil || size != DefaultEDNSUDPSize {
		t.Fatalf("default: size=%d err=%v", size, err)
	}
	size, err = EDNSUDPSizeFromMap(map[string]string{"bufsize": "512"})
	if err != nil || size != 512 {
		t.Fatalf("512: size=%d err=%v", size, err)
	}
}

func TestParseBufsizeFlagCaseFromDog(t *testing.T) {
	// dog uppercases argv before ProcessOptions
	arg := strings.ToUpper("+bufsiz=512")
	val, ok := ParseBufsizeFlag(arg)
	if !ok || val != "512" {
		t.Fatalf("%s: val=%q ok=%v", arg, val, ok)
	}
}
