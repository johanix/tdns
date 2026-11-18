/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

// Package imr is the tdns iterative, validating resolver, to run in an
// application's own process. NewImr builds it and sends nothing; Start primes
// the root and keeps it going; WaitReady, or Ready, says when it can resolve;
// Query looks a name up and validates what it finds, and Serve answers
// requests that come on a channel. Example shows them in order.
//
// # Requiring the module
//
// imr and its four sibling modules, core, cache, edns0 and algorithms, are not
// tagged. imr's go.mod requires the siblings at
// v0.0.0-00010101000000-000000000000 and replaces them with the directories
// beside it, and a replace directive does not carry over to a module that
// requires imr: a `go get` of imr alone fails with "unknown revision
// 000000000000" for all four. A module that uses imr requires all five at the
// same revision REV, a commit of github.com/johanix/tdns, with one go get:
//
//	go get github.com/johanix/tdns/v2/imr@REV github.com/johanix/tdns/v2/core@REV github.com/johanix/tdns/v2/cache@REV github.com/johanix/tdns/v2/edns0@REV github.com/johanix/tdns/v2/algorithms@REV
//
// The modules build against a fork of github.com/miekg/dns. Copy the replace
// line for github.com/miekg/dns from imr/go.mod at REV into your own go.mod,
// for the same reason: without it algorithms does not compile (dns.Algorithm
// and dns.RegisterAlgorithm are undefined).
//
// With both in place, Example compiles in your module as it stands.
package imr
