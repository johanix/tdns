module github.com/johanix/tdns/v2/algorithms

go 1.25.0

require (
	github.com/cloudflare/circl v1.6.3
	github.com/johanix/dnssec-algorithms v0.0.0-20261111143226-7198849ded4b
	github.com/miekg/dns v1.1.70
)

require (
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
)

replace github.com/miekg/dns => github.com/johanix/dns v1.1.72-johanix.6
