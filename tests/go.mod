module github.com/zluudg/tdns/tests

go 1.23.2

replace github.com/zluudg/tdns/stupidns => ../stupidns

require (
	github.com/goccy/go-yaml v1.15.8
	github.com/miekg/dns v1.1.63
)

require (
	github.com/zluudg/tdns/stupidns v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.31.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
)
