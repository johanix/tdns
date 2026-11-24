module github.com/johanix/tdns/v2/imr

go 1.25.2

replace (
	github.com/johanix/tdns/v2/algorithms => ../algorithms
	github.com/johanix/tdns/v2/cache => ../cache
	github.com/johanix/tdns/v2/core => ../core
	github.com/johanix/tdns/v2/edns0 => ../edns0
)

require (
	github.com/johanix/tdns/v2/algorithms v0.0.0-00010101000000-000000000000
	github.com/johanix/tdns/v2/cache v0.0.0-00010101000000-000000000000
	github.com/johanix/tdns/v2/core v0.0.0-00010101000000-000000000000
	github.com/johanix/tdns/v2/edns0 v0.0.0-00010101000000-000000000000
	github.com/miekg/dns v1.1.70
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/johanix/dnssec-algorithms v0.0.0-20261111143226-7198849ded4b // indirect
	github.com/quic-go/quic-go v0.59.1 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
)

// The same replace as every module that requires miekg/dns (see v2/go.mod).
replace github.com/miekg/dns => github.com/johanix/dns v1.1.72-johanix.6
