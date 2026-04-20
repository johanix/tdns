module github.com/johanix/tdns/v2/core

go 1.25.0

require (
	github.com/miekg/dns v1.1.68
	github.com/quic-go/quic-go v0.58.0
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
)

replace github.com/miekg/dns => github.com/johanix/dns v0.0.0-20260419094240-6dbf3c7c5cda
