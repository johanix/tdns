/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Server-wide error registry with clear-ownership subtyping
 * (docs/2026-07-21-server-error-registry-design.md). Standalone by design:
 * low-frequency, multi-writer, plain-mutex server state that shares nothing
 * with the zone snapshot model. Errors are keyed by (Category, Subtype);
 * every mutation goes through a named owned helper so each set/clear point is
 * greppable and located with the code that owns the condition. The generic
 * set/clear are unexported.
 */

package imr

import (
	"fmt"
	"time"
)

type ErrorCategory uint8

const (
	ErrCatTransport ErrorCategory = iota + 1 // a listener/transport is not serving
	ErrCatConfig                             // a configured input is missing/invalid
	ErrCatOther                              // catch-all until a category is defined
	// New categories are APPENDED so existing wire values stay stable.
	ErrCatUpstream // a server this daemon depends on is not answering
)

var errCategoryName = map[ErrorCategory]string{
	ErrCatTransport: "Transport",
	ErrCatConfig:    "Config",
	ErrCatUpstream:  "Upstream",
	ErrCatOther:     "Other",
}

func (c ErrorCategory) String() string {
	if s, ok := errCategoryName[c]; ok {
		return s
	}
	return fmt.Sprintf("Category(%d)", c)
}

type ErrorSubtype uint8

const (
	ErrSubCert        ErrorSubtype = iota + 1 // Transport: cert/key could not be loaded
	ErrSubPort                                // Transport: a listener socket failed to bind
	ErrSubCertMissing                         // Config: a configured cert/key file is absent
	ErrSubImrPriming                          // Upstream: IMR init/root priming failed; the resolver is not serving
	ErrSubImrForward                          // Upstream: one or more IMR forward upstreams are unreachable
	// Config/ImrForwardZone and Config/ImrForwardUpstream are the two halves
	// of forward-table quarantine (#475): a zone with no usable upstream left
	// is not serving, a zone that lost some of them is serving with reduced
	// redundancy. Separate subtypes because `config status` renders one entry
	// per (Category, Subtype), and these two must not read alike.
	ErrSubImrForwardZone     // Config: a forward zone is quarantined; names under it SERVFAIL
	ErrSubImrForwardUpstream // Config: forward upstreams are quarantined; their zones still serve
	ErrSubApiSocket          // Transport: the local admin socket (apiserver.socket) is not served
	ErrSubApiAccess          // Config: the access file (apiserver.access-file) cannot be used
)

var errSubtypeName = map[ErrorSubtype]string{
	ErrSubCert:               "Cert",
	ErrSubPort:               "Port",
	ErrSubCertMissing:        "CertMissing",
	ErrSubImrPriming:         "ImrPriming",
	ErrSubImrForward:         "ImrForward",
	ErrSubImrForwardZone:     "ImrForwardZone",
	ErrSubImrForwardUpstream: "ImrForwardUpstream",
	ErrSubApiSocket:          "ApiSocket",
	ErrSubApiAccess:          "ApiAccess",
}

func (s ErrorSubtype) String() string {
	if n, ok := errSubtypeName[s]; ok {
		return n
	}
	return fmt.Sprintf("Subtype(%d)", s)
}

// ServerError is one active server-wide error condition, identified by its
// (Category, Subtype). Serialized in the config-status API response.
type ServerError struct {
	Category  ErrorCategory `json:"category"`
	Subtype   ErrorSubtype  `json:"subtype"`
	Message   string        `json:"message"`
	FirstSeen time.Time     `json:"first_seen"`
	LastSeen  time.Time     `json:"last_seen"`
}

func (e ServerError) String() string {
	return fmt.Sprintf("[%s/%s] %s", e.Category, e.Subtype, e.Message)
}
