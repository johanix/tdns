package cache

import (
	"context"

	core "github.com/johanix/tdns/tdns/core"
)

// RRFetcher abstracts fetching of signer material used by the DNSSEC validators.
// Implement this on your cache/client to decouple the validators from concrete storage.
type RRFetcher interface {
	// FetchDNSKEY obtains the DNSKEY RRset for the given owner name, or an error.
	FetchDNSKEY(ctx context.Context, name string) (*core.RRset, error)
	// GetDS returns the DS RRset (if any) and whether it is validated.
	GetDS(name string) (*core.RRset, bool)
}


