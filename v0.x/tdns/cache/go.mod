module github.com/johanix/tdns/v0.x/tdns/cache

go 1.24

replace github.com/johanix/tdns/v0.x/tdns/core => ../core

require (
	github.com/johanix/tdns/v0.x/tdns/core v0.0.0-00010101000000-000000000000
	github.com/miekg/dns v1.1.68
	github.com/orcaman/concurrent-map/v2 v2.0.1
)

require (
	github.com/quic-go/quic-go v0.58.0 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
)
