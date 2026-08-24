/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The delegation endpoints (docs/2026-08-11-dsync-api-scheme.md §7.2).
//
// Declarative, not imperative: the child states what its delegation should be
// and the parent computes the change. That mirrors UpdateModeReplace on the
// DSYNC UPDATE path, is idempotent under retry, and keeps the phase-1 statement
// vocabulary off an untrusted surface where every verb would be another thing
// to police.

// DsyncApiRRset is one managed RRset. Owner and type are explicit rather than
// inferred from the records, because an RRset being emptied has no records to
// infer them from -- and "remove the DS" has to be expressible.
//
// The design sketch keyed a map by type alone. That does not survive glue: NS
// lives at the child and its A/AAAA live at the nameserver names, so a map
// keyed by type cannot say WHICH A records to remove.
type DsyncApiRRset struct {
	Owner string   `json:"owner"`
	Type  string   `json:"type"`
	RRs   []string `json:"rrs"`
}

// DsyncApiDelegation is the request and response body.
//
// An RRset listed with an empty RRs is removed. An RRset NOT listed is left
// alone -- not removed. The distinction is the whole reason this is safe to
// use from a client that only manages DS: omitting NS must not wipe it.
type DsyncApiDelegation struct {
	Child  string          `json:"child"`
	RRsets []DsyncApiRRset `json:"rrsets"`
}

// dsyncApiManagedTypes are the types this endpoint will report and accept.
//
// A subset of what a delegation can contain, and deliberately not driven by
// the zone's updatepolicy.child.rrtypes: the policy decides what a given
// principal may CHANGE, while this decides what the endpoint is ABOUT. A
// parent that allowed, say, TXT in its child policy still does not want this
// endpoint used to manage arbitrary text records at a delegation point.
var dsyncApiManagedTypes = []uint16{dns.TypeNS, dns.TypeDS, dns.TypeA, dns.TypeAAAA}

func dsyncApiTypeManaged(rrtype uint16) bool {
	for _, t := range dsyncApiManagedTypes {
		if t == rrtype {
			return true
		}
	}
	return false
}

// dsyncApiError writes a status and a plain-text reason.
//
// Deliberately not JSON and deliberately terse. 401 in particular carries no
// body at all: the credential store answers unknown user, wrong key, disabled
// and expired identically, and that property is worth nothing if the HTTP
// layer then explains which it was.
func dsyncApiError(w http.ResponseWriter, status int, format string, args ...interface{}) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	if format != "" {
		fmt.Fprintf(w, format+"\n", args...)
	}
}

func dsyncApiJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		lgDsyncApi.Error("error encoding DSYNC API response", "err", err)
	}
}

// DsyncApiGetDelegation reports what the parent currently holds for a child.
//
// Read-only and scoped by the same policy as the write: a principal that could
// not change a record does not get to read it here either. The parent's zone
// is public data, so this is a convenience rather than a confidence -- but
// answering more than the policy covers would still be surprising.
func DsyncApiGetDelegation() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		child := dns.Fqdn(strings.TrimSpace(mux.Vars(r)["child"]))
		cred := dsyncApiCredentialFrom(r)
		if cred == nil {
			dsyncApiError(w, http.StatusInternalServerError, "no authenticated principal")
			return
		}
		zd, err := dsyncApiParentZone(child)
		if err != nil {
			dsyncApiError(w, http.StatusNotFound, "%v", err)
			return
		}

		del, err := dsyncApiCurrentDelegation(zd, child, cred.Principal)
		if err != nil {
			dsyncApiError(w, http.StatusInternalServerError, "%v", err)
			return
		}
		dsyncApiJSON(w, http.StatusOK, del)
	}
}

// dsyncApiCurrentDelegation reads the child's delegation out of the parent.
//
// Glue is found by following the NS targets that fall inside the parent zone;
// a nameserver name outside the parent has no glue here by definition.
func dsyncApiCurrentDelegation(zd *ZoneData, child, principal string) (*DsyncApiDelegation, error) {
	del := &DsyncApiDelegation{Child: child}

	owners := []string{child}

	childOwner, err := zd.GetOwner(child)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", child, err)
	}
	if childOwner != nil {
		if nsset, ok := childOwner.RRtypes.Get(dns.TypeNS); ok {
			for _, rr := range nsset.RRs {
				ns, ok := rr.(*dns.NS)
				if !ok {
					continue
				}
				if dns.IsSubDomain(zd.ZoneName, ns.Ns) {
					owners = append(owners, ns.Ns)
				}
			}
		}
	}

	for _, owner := range owners {
		od, err := zd.GetOwner(owner)
		if err != nil || od == nil {
			continue
		}
		for _, rrtype := range dsyncApiManagedTypes {
			// Every managed type is tried at every owner and only what
			// exists is reported. The child apex carries NS and DS, the
			// nameserver names carry addresses, but nothing needs to encode
			// that here -- absence says it.
			rrset, ok := od.RRtypes.Get(rrtype)
			if !ok || len(rrset.RRs) == 0 {
				continue
			}
			// Report only what this principal could also change. Reading is
			// scoped the same way writing is.
			if !nameWithinPrincipalForRead(principal, owner) {
				continue
			}
			out := make([]string, 0, len(rrset.RRs))
			for _, rr := range rrset.RRs {
				out = append(out, rr.String())
			}
			sort.Strings(out)
			del.RRsets = append(del.RRsets, DsyncApiRRset{
				Owner: owner, Type: dns.TypeToString[rrtype], RRs: out,
			})
		}
	}
	return del, nil
}

// nameWithinPrincipalForRead mirrors the selfsub comparison for the read path.
// Always the subtree form: a principal that may change only its own apex can
// still usefully see the glue below it.
func nameWithinPrincipalForRead(principal, owner string) bool {
	return nameWithinPrincipal(principal, owner, true)
}

// DsyncApiPostDelegation applies a declared delegation.
func DsyncApiPostDelegation() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		child := dns.Fqdn(strings.TrimSpace(mux.Vars(r)["child"]))
		cred := dsyncApiCredentialFrom(r)
		if cred == nil {
			dsyncApiError(w, http.StatusInternalServerError, "no authenticated principal")
			return
		}

		zd, err := dsyncApiParentZone(child)
		if err != nil {
			dsyncApiError(w, http.StatusNotFound, "%v", err)
			return
		}

		zd.mu.Lock()
		frozen := zd.Options[OptFrozen]
		policy := zd.UpdatePolicy.Child
		zd.mu.Unlock()

		if frozen {
			dsyncApiError(w, http.StatusConflict,
				"zone %s is frozen; delegation changes are not accepted right now", zd.ZoneName)
			return
		}

		var req DsyncApiDelegation
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			dsyncApiError(w, http.StatusBadRequest, "cannot parse request: %v", err)
			return
		}

		// The child in the body must agree with the child in the path, if it
		// is given at all. Two names that disagree is a client that has built
		// the wrong request, and guessing which one it meant is how the wrong
		// delegation gets changed.
		if strings.TrimSpace(req.Child) != "" &&
			!strings.EqualFold(dns.Fqdn(strings.TrimSpace(req.Child)), child) {
			dsyncApiError(w, http.StatusBadRequest,
				"child in the body (%s) does not match the child in the path (%s)", req.Child, child)
			return
		}
		if len(req.RRsets) == 0 {
			dsyncApiError(w, http.StatusBadRequest,
				"no rrsets in the request; an empty request would mean nothing rather than remove everything")
			return
		}

		actions, err := dsyncApiBuildActions(zd, child, req.RRsets)
		if err != nil {
			dsyncApiError(w, http.StatusBadRequest, "%v", err)
			return
		}
		if len(actions) == 0 {
			dsyncApiError(w, http.StatusBadRequest, "the request produced no changes")
			return
		}

		// Authorization: the zone's own updatepolicy.child, with the
		// authenticated principal where the SIG(0) signer name goes on the
		// DDNS path. Same function, same meaning, different transport.
		if ok, ede := zd.ApproveActionsForPrincipal(policy, cred.Principal, actions, "dsync-api update"); !ok {
			lgDsyncApi.Warn("DSYNC API update refused by policy",
				"zone", zd.ZoneName, "child", child, "principal", cred.Principal, "ede", ede)
			dsyncApiError(w, http.StatusForbidden, "%s", dsyncApiPolicyReason(ede))
			return
		}

		// Coherence: authorised is not the same as correct. The policy above
		// decides whether this principal may touch these RRtypes; it says
		// nothing about whether the delegation that results still works. The
		// parent checks that itself, on every channel, because a check done by
		// the requesting client is not a check.
		if cerr := zd.CheckDelegationCoherenceForUpdate(actions,
			imrDnskeyFetcher(Conf.Internal.ImrEngine)); cerr != nil {
			lgDsyncApi.Warn("DSYNC API update refused as incoherent",
				"zone", zd.ZoneName, "child", child, "principal", cred.Principal, "err", cerr)
			dsyncApiError(w, http.StatusConflict, "%v", cerr)
			return
		}

		if zd.KeyDB == nil || zd.KeyDB.UpdateQ == nil {
			dsyncApiError(w, http.StatusServiceUnavailable, "zone updater is not available")
			return
		}

		// CHILD-UPDATE, not ZONE-UPDATE: delegation data belongs to the
		// configured DelegationBackend. Applying it as ordinary zone content
		// would mutate in-memory state behind the scanner's back, which is the
		// exact disagreement the delegationbackend requirement exists to
		// prevent.
		//
		// PreAuthorized is deliberately NOT set. It means "authorization was
		// settled by possession of the operator API key"; here authorization is
		// the update policy, which has just been applied above and must also
		// hold on the applier's side.
		respch := make(chan ZoneUpdateResult, 1)
		ur := UpdateRequest{
			Cmd:         "CHILD-UPDATE",
			UpdateType:  "DSYNC-API",
			ZoneName:    zd.ZoneName,
			Actions:     actions,
			Validated:   true,
			Trusted:     true,
			Description: fmt.Sprintf("DSYNC API delegation update for %s by %s", child, cred.Principal),
			Resp:        respch,
		}

		ctx := r.Context()
		select {
		case zd.KeyDB.UpdateQ <- ur:
		case <-ctx.Done():
			dsyncApiError(w, http.StatusServiceUnavailable, "request cancelled while queueing the update")
			return
		case <-time.After(5 * time.Second):
			dsyncApiError(w, http.StatusServiceUnavailable, "timed out queueing the update")
			return
		}

		// 200 means applied, persisted and being served -- the same promise
		// phase 2 gave RFC 2136. Answering when the request was merely queued
		// would make it a statement of intent, and the client would have no
		// way to find out later which it had been told.
		select {
		case res := <-respch:
			if res.Err != nil {
				lgDsyncApi.Error("DSYNC API update not applied",
					"zone", zd.ZoneName, "child", child, "err", res.Err)
				dsyncApiError(w, http.StatusServiceUnavailable, "the update was not applied: %v", res.Err)
				return
			}
		case <-ctx.Done():
			// Not cancelled: it is queued and the updater will finish it.
			// Saying "cancelled" would invite a retry on the assumption that
			// nothing happened.
			lgDsyncApi.Warn("DSYNC API client went away mid-apply; the update is NOT cancelled",
				"zone", zd.ZoneName, "child", child)
			return
		case <-time.After(UpdateApplyTimeout):
			lgDsyncApi.Error("DSYNC API update timed out while being applied",
				"zone", zd.ZoneName, "child", child, "timeout", UpdateApplyTimeout)
			dsyncApiError(w, http.StatusServiceUnavailable,
				"timed out after %s waiting for the update to be applied;"+
					" it may or may not have taken effect", UpdateApplyTimeout)
			return
		}

		lgDsyncApi.Info("DSYNC API delegation update applied",
			"zone", zd.ZoneName, "child", child, "principal", cred.Principal, "actions", len(actions))

		del, err := dsyncApiCurrentDelegation(zd, child, cred.Principal)
		if err != nil {
			// The change landed; only the read-back failed. Say so rather than
			// reporting a failure the client would retry.
			lgDsyncApi.Warn("DSYNC API could not read back the delegation", "err", err)
			dsyncApiJSON(w, http.StatusOK, &DsyncApiDelegation{Child: child})
			return
		}
		dsyncApiJSON(w, http.StatusOK, del)
	}
}

// dsyncApiBuildActions turns declared RRsets into update records.
//
// Each entry becomes one statement through BuildZoneUpdateActions -- the same
// builder the management API and the CLI use, so the validation is one
// implementation rather than three. Non-empty is a replacerrset; empty is a
// delrrset.
//
// All of it goes into ONE UpdateRequest: a delegation change that moved NS but
// not glue, because the second half was refused, is worse than one that was
// refused entirely.
func dsyncApiBuildActions(zd *ZoneData, child string, rrsets []DsyncApiRRset) ([]dns.RR, error) {
	var actions []dns.RR
	seen := map[string]bool{}

	for _, set := range rrsets {
		owner := dns.Fqdn(strings.TrimSpace(set.Owner))
		if owner == "." {
			return nil, fmt.Errorf("an rrset entry has no owner")
		}
		rrtype, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(set.Type))]
		if !ok {
			return nil, fmt.Errorf("unknown RR type %q", set.Type)
		}
		if !dsyncApiTypeManaged(rrtype) {
			return nil, fmt.Errorf("this endpoint does not manage %s records", dns.TypeToString[rrtype])
		}

		// Everything must be at or below the child. The update policy would
		// catch most of this, but a child naming a record in a sibling
		// delegation is a malformed request rather than a policy question, and
		// 400 says that more usefully than 403.
		if !dns.IsSubDomain(child, owner) {
			return nil, fmt.Errorf("owner %s is not at or below the child %s", owner, child)
		}

		key := strings.ToLower(owner) + "/" + dns.TypeToString[rrtype]
		if seen[key] {
			return nil, fmt.Errorf("rrset %s %s appears twice", owner, dns.TypeToString[rrtype])
		}
		seen[key] = true

		var spec ZoneUpdateSpec
		if len(set.RRs) == 0 {
			spec = ZoneUpdateSpec{
				Verb:   VerbDelRRset,
				Name:   owner,
				Rrtype: dns.TypeToString[rrtype],
			}
		} else {
			// Every record must match the owner and type it was filed under.
			// Otherwise a client could smuggle a change to another name into
			// an entry that looks like it is about this one.
			for _, s := range set.RRs {
				rr, err := dns.NewRR(s)
				if err != nil {
					return nil, fmt.Errorf("cannot parse %q: %v", s, err)
				}
				if !strings.EqualFold(rr.Header().Name, owner) {
					return nil, fmt.Errorf("record %q is not at the declared owner %s", s, owner)
				}
				if rr.Header().Rrtype != rrtype {
					return nil, fmt.Errorf("record %q is not a %s record", s, dns.TypeToString[rrtype])
				}
			}
			spec = ZoneUpdateSpec{Verb: VerbReplaceRRset, RRs: set.RRs}
		}

		built, err := BuildZoneUpdateActions(zd.ZoneName, spec)
		if err != nil {
			return nil, err
		}
		actions = append(actions, built...)
	}
	return actions, nil
}

// dsyncApiPolicyReason renders a refusal the way the DDNS path would have
// reported it, so the two transports diagnose alike.
func dsyncApiPolicyReason(ede uint16) string {
	if s, ok := edeToDsyncApiReason[ede]; ok {
		return s
	}
	return "refused by the parent zone's update policy"
}

var edeToDsyncApiReason = map[uint16]string{
	edns0.EDEZoneUpdateRRtypeNotAllowed:   "the parent zone's update policy does not allow this RR type to be changed",
	edns0.EDEZoneUpdateOwnerOutsidePolicy: "the parent zone's update policy does not place this name under your principal",
	edns0.EDEZoneUpdatesNotAllowed:        "the parent zone's update policy does not allow updates",
}
