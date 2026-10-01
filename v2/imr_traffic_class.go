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
//
// The mark also decides one thing about the answer: whether a DS or DNSKEY
// question follows a CNAME at the query name (followsCNAME, #875). A client's
// does, as for any other type; the resolver's own does not.

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

// isClientQuery reports whether ctx carries a DNS client's query: marked by
// withClientQuery, and not marked again by withOwnTraffic.
func isClientQuery(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	client, _ := ctx.Value(queryOriginKey{}).(bool)
	return client
}

// trafficClass is the class an answer is counted under: the client's privacy
// level when ctx carries a client query, and internal otherwise.
func trafficClass(ctx context.Context, privacy edns0.PrivacyLevel) cache.TrafficClass {
	if !isClientQuery(ctx) {
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

// imrQueryAsClientKey marks a context whose ImrQuery asks its question as a DNS
// client does (asClientQuery).
type imrQueryAsClientKey struct{}

// asClientQuery marks ctx for ImrQuery to ask its question as a DNS client's
// query (withClientQuery) rather than as the resolver's own lookup: a DS or
// DNSKEY question then follows a CNAME at the query name (followsCNAME), and
// the answers are counted under the client classes. Lookups nested inside
// that query are the resolver's own again (imrQueryContext).
//
// No caller uses it yet. ImrQuery's callers -- the scanner, the delegation
// checks, the DSYNC lookups, "imr query" over the API -- ask about the name
// itself, and a DS or DNSKEY at a CNAME owner comes back as "none there", with
// the CNAME's verdict (#875). A caller that wants the answer a DNS client gets
// puts this mark on its context.
func asClientQuery(ctx context.Context) context.Context {
	return context.WithValue(ctx, imrQueryAsClientKey{}, true)
}

// imrQueryContext is the context ImrQuery's lookups run on: the resolver's own
// lookup, unless the caller marked ctx with asClientQuery. The mark is taken
// off, so that an ImrQuery nested inside is the resolver's own.
func imrQueryContext(ctx context.Context) context.Context {
	if asClient, _ := ctx.Value(imrQueryAsClientKey{}).(bool); asClient {
		return withClientQuery(context.WithValue(ctx, imrQueryAsClientKey{}, false))
	}
	return withOwnTraffic(ctx)
}
