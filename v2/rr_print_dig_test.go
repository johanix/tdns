package tdns

import "testing"

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
