/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

// Package delegationtest is the delegation store equivalence suite: one table
// of behaviours every tdns.DelegationStore must show, run by each store's own
// tests -- the sqlite store from v2, the external-db store from its module.
// Two stores behind one interface that disagree on any of these would make
// the (store, writer) split a lie (docs/2026-09-08-childsync-proxy.md §10).
//
// It is a separate package rather than a helper inside package tdns because
// the external-db module imports tdns and could not otherwise share it, and
// a separate package rather than a test file so that it can be imported.
package delegationtest

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

const parent = "parent.example."

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

func update(t *testing.T, class uint16, rrs ...string) tdns.UpdateRequest {
	t.Helper()
	ur := tdns.UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: parent}
	for _, s := range rrs {
		rr := mustRR(t, s)
		rr.Header().Class = class
		if class != dns.ClassINET {
			rr.Header().Ttl = 0
		}
		ur.Actions = append(ur.Actions, rr)
	}
	return ur
}

func count(data map[string]map[uint16][]dns.RR, owner string, rrtype uint16) int {
	return len(data[owner][rrtype])
}

// RunStoreSuite runs the suite against stores newStore builds. Every subtest
// gets a fresh, empty store.
func RunStoreSuite(t *testing.T, newStore func(t *testing.T) tdns.DelegationStore) {
	t.Run("EmptyChildIsEmptyNotError", func(t *testing.T) {
		s := newStore(t)
		data, err := s.GetDelegationData(parent, "nobody.parent.example.")
		if err != nil {
			t.Fatalf("a child with no rows must not be an error: %v", err)
		}
		if data == nil || len(data) != 0 {
			t.Fatalf("want an empty map, got %v", data)
		}
		kids, err := s.ListChildren(parent)
		if err != nil {
			t.Fatalf("ListChildren on an empty store: %v", err)
		}
		if len(kids) != 0 {
			t.Fatalf("an empty store lists children: %v", kids)
		}
	})

	t.Run("AddThenRead", func(t *testing.T) {
		s := newStore(t)
		if err := s.ApplyChildUpdate(parent, update(t, dns.ClassINET,
			"alpha.parent.example. 3600 IN NS ns.alpha.parent.example.",
			"ns.alpha.parent.example. 3600 IN A 192.0.2.51",
		)); err != nil {
			t.Fatalf("ApplyChildUpdate: %v", err)
		}
		data, err := s.GetDelegationData(parent, "alpha.parent.example.")
		if err != nil {
			t.Fatalf("GetDelegationData: %v", err)
		}
		if count(data, "alpha.parent.example.", dns.TypeNS) != 1 || count(data, "ns.alpha.parent.example.", dns.TypeA) != 1 {
			t.Fatalf("stored delegation does not read back: %v", data)
		}
		// Glue is filed under the CHILD it belongs to, not under its own name.
		if glue, _ := s.GetDelegationData(parent, "ns.alpha.parent.example."); len(glue) != 0 {
			t.Errorf("glue was filed as a child of its own: %v", glue)
		}
		kids, _ := s.ListChildren(parent)
		if len(kids) != 1 || kids[0] != "alpha.parent.example." {
			t.Fatalf("ListChildren = %v, want [alpha.parent.example.]", kids)
		}
	})

	t.Run("StoredRRsAreNormalised", func(t *testing.T) {
		s := newStore(t)
		if err := s.ApplyChildUpdate(parent, update(t, dns.ClassINET,
			"alpha.parent.example. 12345 IN NS ns.alpha.parent.example.")); err != nil {
			t.Fatalf("ApplyChildUpdate: %v", err)
		}
		data, _ := s.GetDelegationData(parent, "alpha.parent.example.")
		rr := data["alpha.parent.example."][dns.TypeNS][0]
		if rr.Header().Ttl != 0 || rr.Header().Class != dns.ClassINET {
			t.Fatalf("stored RR keeps the update's TTL or class: %s", rr)
		}
	})

	t.Run("AddIsIdempotent", func(t *testing.T) {
		s := newStore(t)
		ur := update(t, dns.ClassINET, "alpha.parent.example. 3600 IN NS ns.alpha.parent.example.")
		for i := 0; i < 2; i++ {
			if err := s.ApplyChildUpdate(parent, ur); err != nil {
				t.Fatalf("ApplyChildUpdate #%d: %v", i+1, err)
			}
		}
		data, _ := s.GetDelegationData(parent, "alpha.parent.example.")
		if count(data, "alpha.parent.example.", dns.TypeNS) != 1 {
			t.Fatalf("the same record added twice is stored twice: %v", data)
		}
	})

	t.Run("DeleteRR", func(t *testing.T) {
		s := newStore(t)
		if err := s.ApplyChildUpdate(parent, update(t, dns.ClassINET,
			"alpha.parent.example. 3600 IN NS ns1.alpha.parent.example.",
			"alpha.parent.example. 3600 IN NS ns2.alpha.parent.example.")); err != nil {
			t.Fatal(err)
		}
		if err := s.ApplyChildUpdate(parent, update(t, dns.ClassNONE,
			"alpha.parent.example. 3600 IN NS ns1.alpha.parent.example.")); err != nil {
			t.Fatalf("delete-RR: %v", err)
		}
		data, _ := s.GetDelegationData(parent, "alpha.parent.example.")
		nss := data["alpha.parent.example."][dns.TypeNS]
		if len(nss) != 1 || nss[0].(*dns.NS).Ns != "ns2.alpha.parent.example." {
			t.Fatalf("after deleting ns1, want exactly ns2, got %v", nss)
		}
	})

	t.Run("DeleteRRsetEmptiesTheChild", func(t *testing.T) {
		s := newStore(t)
		if err := s.ApplyChildUpdate(parent, update(t, dns.ClassINET,
			"alpha.parent.example. 3600 IN NS ns1.alpha.parent.example.",
			"alpha.parent.example. 3600 IN NS ns2.alpha.parent.example.")); err != nil {
			t.Fatal(err)
		}
		if err := s.ApplyChildUpdate(parent, update(t, dns.ClassANY,
			"alpha.parent.example. 3600 IN NS .")); err != nil {
			t.Fatalf("delete-RRset: %v", err)
		}
		data, err := s.GetDelegationData(parent, "alpha.parent.example.")
		if err != nil || len(data) != 0 {
			t.Fatalf("after deleting the RRset: data=%v err=%v", data, err)
		}
		if kids, _ := s.ListChildren(parent); len(kids) != 0 {
			t.Fatalf("a child with no rows is still listed: %v", kids)
		}
	})

	t.Run("OneUpdateIsOneIntent", func(t *testing.T) {
		// A replace -- remove one NS, add another -- arrives as one update,
		// and the store ends up with exactly the new state.
		s := newStore(t)
		if err := s.ApplyChildUpdate(parent, update(t, dns.ClassINET,
			"alpha.parent.example. 3600 IN NS old.alpha.parent.example.")); err != nil {
			t.Fatal(err)
		}
		ur := update(t, dns.ClassNONE, "alpha.parent.example. 3600 IN NS old.alpha.parent.example.")
		ur.Actions = append(ur.Actions, update(t, dns.ClassINET, "alpha.parent.example. 3600 IN NS new.alpha.parent.example.").Actions...)
		if err := s.ApplyChildUpdate(parent, ur); err != nil {
			t.Fatalf("replace: %v", err)
		}
		data, _ := s.GetDelegationData(parent, "alpha.parent.example.")
		nss := data["alpha.parent.example."][dns.TypeNS]
		if len(nss) != 1 || nss[0].(*dns.NS).Ns != "new.alpha.parent.example." {
			t.Fatalf("after the replace, want exactly the new NS, got %v", nss)
		}
	})

	t.Run("AnUnknownClassFailsTheWholeUpdate", func(t *testing.T) {
		// A class other than IN, NONE or ANY is a defect in the update.
		// The store must not apply the rest and answer NOERROR: nothing of
		// the update may be kept.
		s := newStore(t)
		ur := update(t, dns.ClassINET, "alpha.parent.example. 3600 IN NS ns.alpha.parent.example.")
		odd := mustRR(t, "alpha.parent.example. 3600 IN NS ns2.alpha.parent.example.")
		odd.Header().Class = dns.ClassCHAOS
		ur.Actions = append(ur.Actions, odd)
		if err := s.ApplyChildUpdate(parent, ur); err == nil {
			t.Fatal("an update with an action of unknown class was accepted")
		}
		data, err := s.GetDelegationData(parent, "alpha.parent.example.")
		if err != nil || len(data) != 0 {
			t.Fatalf("part of a refused update was kept: data=%v err=%v", data, err)
		}
	})

	t.Run("ChildrenAreScopedToTheirParent", func(t *testing.T) {
		s := newStore(t)
		if err := s.ApplyChildUpdate(parent, update(t, dns.ClassINET,
			"alpha.parent.example. 3600 IN NS ns.alpha.parent.example.")); err != nil {
			t.Fatal(err)
		}
		if kids, _ := s.ListChildren("other.example."); len(kids) != 0 {
			t.Fatalf("another parent sees this parent's children: %v", kids)
		}
	})

	t.Run("AdoptOnlyIntoAnEmptyChild", func(t *testing.T) {
		s := newStore(t)
		a, ok := s.(tdns.DelegationAdopter)
		if !ok {
			t.Skip("store does not adopt")
		}
		rrs := []dns.RR{
			mustRR(t, "alpha.parent.example. 3600 IN NS ns.alpha.parent.example."),
			mustRR(t, "ns.alpha.parent.example. 3600 IN A 192.0.2.51"),
		}
		n, err := a.AdoptChildDelegation(parent, "alpha.parent.example.", rrs)
		if err != nil || n != 2 {
			t.Fatalf("first adoption: n=%d err=%v, want 2 rows", n, err)
		}
		n, err = a.AdoptChildDelegation(parent, "alpha.parent.example.", rrs)
		if err != nil || n != 0 {
			t.Fatalf("second adoption: n=%d err=%v, want nothing written", n, err)
		}
		// A child's assertion of a different NS afterwards is what the
		// store holds, alongside what was observed for other owners.
		if err := s.ApplyChildUpdate(parent, update(t, dns.ClassINET,
			"alpha.parent.example. 3600 IN NS ns2.alpha.parent.example.")); err != nil {
			t.Fatal(err)
		}
		data, _ := s.GetDelegationData(parent, "alpha.parent.example.")
		if count(data, "alpha.parent.example.", dns.TypeNS) != 2 || count(data, "ns.alpha.parent.example.", dns.TypeA) != 1 {
			t.Fatalf("after adopt + assert: %v", data)
		}
	})
}
