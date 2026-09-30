/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/edns0"
)

// Whose query is this? The transport stats count each answer from an auth
// server by the query that caused it: a DNS client's, by the PRIVACY level it
// carried, or the resolver's own. The level alone cannot tell them apart: the
// resolver's own lookups -- DNSKEY and DS for validation, nameserver
// addresses, transport signals, priming -- all go out with PrivacyNone, as a
// client query without PRIVACY does. So the client path marks its context
// (ImrResponder), and the own lookups that run inside a client's query mark
// theirs back. A context without a mark is not a DNS client's: the transport
// signal and TLSA lookups start from a context of their own, and the embedded
// users (the scanner, the DSYNC lookups, "imr query" over the API) never had
// one.

type queryOriginKey struct{}

// withClientQuery marks ctx as a DNS client's query.
func withClientQuery(ctx context.Context) context.Context {
	return context.WithValue(ctx, queryOriginKey{}, true)
}

// withOwnTraffic marks ctx as the resolver's own lookup, also when it runs
// inside a client's query.
func withOwnTraffic(ctx context.Context) context.Context {
	return context.WithValue(ctx, queryOriginKey{}, false)
}

// trafficClass is the class an answer is counted under: the client's privacy
// level when ctx carries a client query, and internal otherwise.
func trafficClass(ctx context.Context, privacy edns0.PrivacyLevel) cache.TrafficClass {
	if ctx == nil {
		return cache.ClassInternal
	}
	if client, _ := ctx.Value(queryOriginKey{}).(bool); !client {
		return cache.ClassInternal
	}
	switch privacy {
	case edns0.PrivacyOpportunistic:
		return cache.ClassOpportunistic
	case edns0.PrivacyStrict:
		return cache.ClassStrict
	}
	return cache.ClassNone
}
