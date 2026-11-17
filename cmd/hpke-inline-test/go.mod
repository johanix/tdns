module github.com/johanix/tdns/cmd/hpke-inline-test

go 1.26.0

require github.com/johanix/tdns/v2/hpke v0.0.0

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/miekg/dns v1.1.70 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)

replace github.com/johanix/tdns/v2/hpke => ../../v2/hpke
