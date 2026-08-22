package cli

import (
	"path/filepath"
	"testing"
)

// The CA copy belongs one level above the per-host leaves, because every
// consumer on the host shares it: ca-file for XoT, cacert for tdns-cli. It
// used to be written beside the leaves, where nothing looked for it, while
// this command's own printed advice named the directory above -- so the
// instructions were wrong about the file the command had just written.
func TestCACopyPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		certFile string
		want     string
	}{
		{
			name:     "climbs out of servers/",
			certFile: "/etc/tdns/certs/servers/ns1.example.com.crt",
			want:     "/etc/tdns/certs/tdns-ca.crt",
		},
		{
			// Not the documented layout, so nothing is assumed about the
			// parent: the copy stays where the operator pointed. Writing to
			// filepath.Dir unconditionally would put it in /etc/tdns here,
			// outside the directory that was named.
			name:     "leaves a non-servers directory alone",
			certFile: "/etc/tdns/certs/ns1.example.com.crt",
			want:     "/etc/tdns/certs/tdns-ca.crt",
		},
		{
			name:     "relative paths keep their shape",
			certFile: filepath.Join("certs", "servers", "ns1.example.com.crt"),
			want:     filepath.Join("certs", "tdns-ca.crt"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := caCopyPath(tc.certFile); got != tc.want {
				t.Errorf("caCopyPath(%q) = %q, want %q", tc.certFile, got, tc.want)
			}
		})
	}
}
