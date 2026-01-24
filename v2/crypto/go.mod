module github.com/johanix/tdns/v2/crypto

go 1.25.2

replace github.com/johanix/tdns/v2/hpke => ../hpke

require (
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/johanix/tdns/v2/hpke v0.0.0-00010101000000-000000000000
)

require (
	github.com/cloudflare/circl v1.6.2 // indirect
	github.com/miekg/dns v1.1.70 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)
