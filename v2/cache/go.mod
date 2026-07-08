module github.com/johanix/tdns/v2/cache

go 1.25.0

replace github.com/johanix/tdns/v2/core => ../core

require (
	github.com/johanix/tdns/v2/core v0.0.0-00010101000000-000000000000
	github.com/miekg/dns v1.1.68
)

require (
	github.com/quic-go/quic-go v0.59.1 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
)

replace github.com/miekg/dns => github.com/johanix/dns v0.0.0-20260608092609-2a28f8f1484d
