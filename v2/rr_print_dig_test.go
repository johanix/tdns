package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

func TestDigStyleServer(t *testing.T) {
	cases := []struct {
		host, port, want string
	}{
		{"127.0.0.1", "5354", "127.0.0.1#5354(127.0.0.1)"},
		{"127.0.0.1", "53", "127.0.0.1#53(127.0.0.1)"},
		{"127.0.0.1", "", "127.0.0.1#53(127.0.0.1)"},
		{"::1", "5354", "[::1]#5354([::1])"},
		{"https://example.com/dns-query", "443", "https://example.com/dns-query"},
	}
	for _, c := range cases {
		if got := digStyleServer(c.host, c.port); got != c.want {
			t.Errorf("digStyleServer(%q, %q) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestPaddingOptionString(t *testing.T) {
	cases := []struct {
		name string
		pad  []byte
		want string
	}{
		{"empty", nil, "PADDING: 0 octets"},
		{"zeros", make([]byte, 365), "PADDING: 365 octets"},
		{"non-zero", []byte{0, 0, 7, 0}, "PADDING: 4 octets (not all zero)"},
	}
	for _, c := range cases {
		got := paddingOptionString(&dns.EDNS0_PADDING{Padding: c.pad})
		if got != c.want {
			t.Errorf("%s: paddingOptionString = %q, want %q", c.name, got, c.want)
		}
	}
}
