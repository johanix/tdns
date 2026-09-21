/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A zone's first content as a transaction, through the real joins: the markers
// on the update queue, the first snapshot of a zone that signs, and the whole
// of it seen from a secondary.

func txTestPolicy() *DnssecPolicy {
	return &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity:  PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
	}
}

// startTxUpdater runs the zone updater for one test. A key store made by
// NewKeyDB alone has an unbuffered queue; the engine being there is what lets
// a writer's sends return.
func startTxUpdater(t *testing.T, kdb *KeyDB) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = kdb.ZoneUpdaterEngine(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the zone updater did not stop")
		}
	})
}

// sendTx queues one request and, when wait is set, returns what its Resp said.
func sendTx(t *testing.T, kdb *KeyDB, ur UpdateRequest, wait bool) ZoneUpdateResult {
	t.Helper()
	if wait {
		ur.Resp = make(chan ZoneUpdateResult, 1)
	}
	select {
	case kdb.UpdateQ <- ur:
	case <-time.After(5 * time.Second):
		t.Fatalf("the update queue did not take %s", ur.Cmd)
	}
	if !wait {
		return ZoneUpdateResult{}
	}
	select {
	case res := <-ur.Resp:
		return res
	case <-time.After(10 * time.Second):
		t.Fatalf("no answer to %s within 10 s", ur.Cmd)
	}
	return ZoneUpdateResult{}
}

// A writer that queues its changes queues its markers: begin, changes and
// commit are applied in the order sent, and the commit's Resp says the
// transaction is published.
func TestTheMarkersTravelTheUpdateQueue(t *testing.T) {
	const zone = "markers.tx.example."
	zd, kdb := newPublishedAutoZone(t, zone)
	startTxUpdater(t, kdb)
	before := readPublishState(zd)

	res := sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxBegin, ZoneName: zone, TxID: "writer-1", TxFlags: TxUrgent}, true)
	if res.Err != nil {
		t.Fatalf("TX-BEGIN: %v", res.Err)
	}
	if n := zd.txOpenCount(); n != 1 {
		t.Fatalf("%d open transactions after TX-BEGIN, want 1", n)
	}
	if res := sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxBegin, ZoneName: zone, TxID: "writer-1"}, true); res.Err == nil {
		t.Error("a second TX-BEGIN with an id that is already open was accepted")
	}

	for i := 0; i < 3; i++ {
		ur := txtUpdate(t, zd, fmt.Sprintf("r%d.%s", i, zone), "queued")
		if res := sendTx(t, kdb, ur, true); res.Err != nil {
			t.Fatalf("update %d: %v", i, res.Err)
		}
	}
	if readPublishState(zd).snap != before.snap {
		t.Fatal("a queued update published a held zone")
	}

	if res := sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxCommit, ZoneName: zone, TxID: "no-such-writer"}, true); res.Err == nil {
		t.Error("TX-COMMIT for an unknown transaction was accepted")
	}
	if readPublishState(zd).snap != before.snap {
		t.Fatal("a commit for an unknown transaction published the zone")
	}

	res = sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxCommit, ZoneName: zone, TxID: "writer-1"}, true)
	if res.Err != nil || !res.Applied {
		t.Fatalf("TX-COMMIT: applied=%v err=%v", res.Applied, res.Err)
	}
	// The Resp is the promise: the transaction is published when it arrives.
	for i := 0; i < 3; i++ {
		if owner := fmt.Sprintf("r%d.%s", i, zone); !served(zd, owner, dns.TypeTXT) {
			t.Errorf("%s is not served when the commit's Resp arrives", owner)
		}
	}
	after := readPublishState(zd)
	if after.serial == before.serial {
		t.Error("the commit did not bump the serial")
	}
	if n := len(after.snap.IxfrChain) - len(before.snap.IxfrChain); n > 1 {
		t.Errorf("the transaction published as %d IXFR links, want one", n)
	}
}

// A zone that may not originate content (on tdns-auth, a secondary that does
// not sign inline) has nothing of ours to group, and a hold would stop its
// refresh publishes. Both ways to open a transaction refuse it: the queued
// TX-BEGIN and the in-process BeginTx.
func TestATransactionIsRefusedOnAZoneThatMayNotOriginate(t *testing.T) {
	// The origination gates engage on tdns-auth only. Set before the zone and
	// its goroutines exist, restored after they are gone (cleanups run last
	// registered first).
	saved := Globals.App.Type
	Globals.App.Type = AppTypeAuth
	t.Cleanup(func() { Globals.App.Type = saved })

	const zone = "secondary.tx.example."
	zd, kdb := newPublishedAutoZone(t, zone)
	startTxUpdater(t, kdb)
	zd.mu.Lock()
	zd.ZoneType = Secondary
	delete(zd.Options, OptInlineSigning)
	zd.mu.Unlock()
	if zoneMayOriginateContent(zd) {
		t.Fatal("precondition: the zone may originate content")
	}

	if res := sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxBegin, ZoneName: zone, TxID: "writer-1"}, true); res.Err == nil {
		t.Error("a queued TX-BEGIN on a zone that may not originate content was accepted")
	}
	if id, err := zd.BeginTx(0); err == nil {
		t.Errorf("BeginTx on a zone that may not originate content opened %q", id)
	} else if id != "" {
		t.Errorf("a refused BeginTx returned the id %q", id)
	}
	if n := zd.txOpenCount(); n != 0 {
		t.Errorf("%d transaction(s) open on a zone that may not originate content", n)
	}

	// The role is the reason. Accepted: the sanctioned exception, a secondary
	// that signs inline (it originates its signatures), and the same zone as a
	// primary.
	for _, c := range []struct {
		name   string
		ztype  ZoneType
		inline bool
	}{
		{"an inline-signing secondary", Secondary, true},
		{"a primary", Primary, false},
	} {
		zd.mu.Lock()
		zd.ZoneType = c.ztype
		if c.inline {
			zd.Options[OptInlineSigning] = true
		} else {
			delete(zd.Options, OptInlineSigning)
		}
		zd.mu.Unlock()
		id, err := zd.BeginTx(0)
		if err != nil {
			t.Errorf("BeginTx on %s: %v", c.name, err)
			continue
		}
		if err := zd.CommitTx(id); err != nil {
			t.Errorf("CommitTx on %s: %v", c.name, err)
		}
	}
}

// A plain commit on a busy Ready zone asks the gate, and the publish happens in
// the publisher's goroutine, where the commit's handler cannot see its outcome.
// The commit's Resp is kept on the zone and answered by the publish that
// carries the transaction.
func TestACommitsRespIsAnsweredByTheGatesPublish(t *testing.T) {
	const zone = "waiter.tx.example."
	zd, kdb := newPublishedAutoZone(t, zone)
	startTxUpdater(t, kdb)
	zd.mu.Lock()
	zd.publishCadence = 400 * time.Millisecond
	zd.mu.Unlock()
	if _, err := zd.Publish(); err != nil { // busy: it published just now
		t.Fatalf("Publish: %v", err)
	}
	busy := readPublishState(zd)

	sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxBegin, ZoneName: zone, TxID: "plain"}, false)
	sendTx(t, kdb, txtUpdate(t, zd, "a."+zone, "one"), false)
	start := time.Now()
	res := sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxCommit, ZoneName: zone, TxID: "plain"}, true)
	if res.Err != nil || !res.Applied {
		t.Fatalf("TX-COMMIT: applied=%v err=%v", res.Applied, res.Err)
	}
	if !served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatal("the commit's Resp arrived before the transaction was published")
	}
	if waited := time.Since(start); waited < 200*time.Millisecond {
		t.Errorf("the commit was answered after %v on a busy zone with a 400 ms cadence: it did not go through the gate", waited)
	}
	if readPublishState(zd).snap == busy.snap {
		t.Error("nothing was published")
	}
}

// newHeldSigningZone is a zone created held that signs its own content, set up
// the way an identity zone is: the options and the policy after creation.
func newHeldSigningZone(t *testing.T, zone string, policy *DnssecPolicy) (*ZoneData, TxID, *KeyDB) {
	t.Helper()
	zd, id, kdb := newHeldAutoZone(t, zone)
	zd.mu.Lock()
	zd.Options[OptAllowUpdates] = true
	zd.Options[OptOnlineSigning] = true
	zd.DnssecPolicy = policy
	zd.Notify = []PeerConf{{Addr: "127.0.0.1:53", Key: NOKEY}}
	zd.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}}
	zd.mu.Unlock()
	return zd, id, kdb
}

// unsignedRRsets lists the authoritative RRsets of a snapshot that carry no
// RRSIG, and says whether the zone has an NSEC chain at all.
func unsignedRRsets(snap *zoneSnapshot) (unsigned []string, nsecs int) {
	for name, od := range snap.Data {
		if od == nil || od.RRtypes == nil {
			continue
		}
		for _, rrtype := range od.RRtypes.Keys() {
			if rrtype == dns.TypeRRSIG {
				continue
			}
			rs, _ := od.RRtypes.Get(rrtype)
			if len(rs.RRs) > 0 && len(rs.RRSIGs) == 0 {
				unsigned = append(unsigned, name+"/"+dns.TypeToString[rrtype])
			}
		}
		if len(od.NSEC.RRs) > 0 {
			nsecs++
			if len(od.NSEC.RRSIGs) == 0 {
				unsigned = append(unsigned, name+"/NSEC")
			}
		}
	}
	sort.Strings(unsigned)
	return unsigned, nsecs
}

func drainNotifies(q chan NotifyRequest) int {
	n := 0
	for {
		select {
		case <-q:
			n++
		default:
			return n
		}
	}
}

// Signed or nothing, the signed half. In #653 the intermediate serial was
// signed: the denial that did the damage carried a valid RRSIG. A signing pass
// that published during the hold would recreate exactly that. And the commit's
// snapshot is the complete signed zone whoever staged what and when: a record
// staged before the keys existed, one the signing pass signed, and one staged
// after it that no pass has seen.
func TestTheFirstSnapshotOfASigningZoneIsSigned(t *testing.T) {
	const zone = "signed.tx.example."
	notifies := withNotifyQ(t, 8)
	zd, id, kdb := newHeldSigningZone(t, zone, txTestPolicy())

	stageTxt(t, zd, "early."+zone, "before the keys")
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone during the hold: %v", err)
	}
	if zd.publishedSnapshot() != nil {
		t.Fatal("a signing pass published a held zone: a signed, partial zone is visible")
	}
	stageTxt(t, zd, "late."+zone, "after the signing pass")
	if n := drainNotifies(notifies); n != 0 {
		t.Fatalf("%d NOTIFY during the hold", n)
	}

	// What the outside sees of a held zone: SERVFAIL, which no resolver caches
	// as a denial, and no transfer.
	q := new(dns.Msg)
	q.SetQuestion("early."+zone, dns.TypeTXT)
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(q)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	qw := &fakeRW{remote: udpAddr("127.0.0.1")}
	if err := zd.QueryResponder(context.Background(), qw, q, "early."+zone, dns.TypeTXT, msgo, kdb, nil); err != nil {
		t.Fatalf("QueryResponder: %v", err)
	}
	if qw.written == nil || qw.written.Rcode != dns.RcodeServerFailure {
		t.Errorf("a query into a held zone: %v, want SERVFAIL", qw.written)
	}
	x := new(dns.Msg)
	x.SetAxfr(zone)
	xw := &fakeRW{remote: udpAddr("127.0.0.1")}
	if sent, _ := zd.ZoneTransferOut(context.Background(), xw, x, nil); sent != 0 ||
		xw.written == nil || xw.written.Rcode != dns.RcodeRefused {
		t.Errorf("a transfer of a held zone: %d RRs sent, response %v, want REFUSED", sent, xw.written)
	}

	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("the commit installed no snapshot")
	}
	for _, owner := range []string{"early." + zone, "late." + zone} {
		if !served(zd, owner, dns.TypeTXT) {
			t.Errorf("%s is not in the first snapshot", owner)
		}
	}
	if !served(zd, zone, dns.TypeDNSKEY) {
		t.Error("the first snapshot has no DNSKEY RRset")
	}
	unsigned, nsecs := unsignedRRsets(snap)
	if len(unsigned) > 0 {
		t.Errorf("the first snapshot of a signing zone has unsigned RRsets: %v", unsigned)
	}
	if nsecs == 0 {
		t.Error("the first snapshot of a signing zone has no NSEC chain")
	}
	if !zd.Ready {
		t.Error("the zone is not Ready after a signed first snapshot")
	}
	if n := drainNotifies(notifies); n != 1 {
		t.Errorf("%d NOTIFYs for the first snapshot, want one", n)
	}
}

// Signed or nothing, the nothing half. "Cannot sign yet" means "publish
// unsigned and stay not Ready" today, and an unsigned snapshot is queryable. A
// first content that cannot be signed installs nothing, whichever publish would
// have installed it, and is retried by the next signing pass.
func TestAFirstContentThatCannotBeSignedInstallsNothing(t *testing.T) {
	const zone = "unsigned.tx.example."
	notifies := withNotifyQ(t, 8)
	zd, id, kdb := newHeldSigningZone(t, zone, nil) // no policy bound: "not yet"

	stageTxt(t, zd, "a."+zone, "one")
	err := zd.CommitTx(id)
	if err == nil {
		t.Error("a commit that installed nothing reported success")
	}
	if zd.publishedSnapshot() != nil {
		t.Fatal("a signing zone's first content was published unsigned")
	}
	if !zd.HasError(FirstPublishError) {
		t.Error("the zone's status does not carry the reason")
	}
	if zd.HasError(DnssecError) {
		t.Error("\"not yet\" was recorded as DnssecError, which makes every signing pass refuse the zone: the retry is switched off")
	}
	// The transaction is over; nothing more is coming from its writer.
	if n := zd.txOpenCount(); n != 0 {
		t.Errorf("%d transaction(s) open after the commit", n)
	}
	zd.mu.Lock()
	queued := zd.publishQueued
	zd.mu.Unlock()
	if queued {
		t.Error("a publish stayed queued after the refusal; the publisher's loop will retry it hot")
	}

	// The hold is closed, so the next publisher to arrive reaches the first
	// snapshot. It installs nothing either, and the zone is still no draft.
	stageTxt(t, zd, "b."+zone, "two")
	if _, err := zd.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	zd.requestPublish(false)
	time.Sleep(100 * time.Millisecond)
	if zd.publishedSnapshot() != nil {
		t.Fatal("a later publish installed the unsigned first content")
	}

	// The missing thing arrives, and the pass that runs when it does is the
	// retry.
	zd.mu.Lock()
	zd.DnssecPolicy = txTestPolicy()
	zd.mu.Unlock()
	if _, err := zd.SignZone(context.Background(), kdb, false); err != nil {
		t.Fatalf("SignZone after the policy bound: %v", err)
	}
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("the signing pass did not install the first snapshot")
	}
	for _, owner := range []string{"a." + zone, "b." + zone} {
		if !served(zd, owner, dns.TypeTXT) {
			t.Errorf("%s is not in the first snapshot", owner)
		}
	}
	if unsigned, _ := unsignedRRsets(snap); len(unsigned) > 0 {
		t.Errorf("unsigned RRsets in the first snapshot: %v", unsigned)
	}
	if !zd.Ready {
		t.Error("the zone is not Ready")
	}
	if zd.HasError(FirstPublishError) {
		t.Error("the error outlived the first publish")
	}
	if n := drainNotifies(notifies); n != 1 {
		t.Errorf("%d NOTIFYs, want one", n)
	}
}

// The other retry: the creator commits again. TX-COMMIT on a zone whose first
// content is committed and unsigned is accepted and tries the publish again;
// its Resp carries the outcome. A creator that wants a schedule has one it
// controls.
func TestARepeatedCommitRetriesAnUnsignedFirstContent(t *testing.T) {
	const zone = "again.tx.example."
	zd, id, kdb := newHeldSigningZone(t, zone, nil)
	startTxUpdater(t, kdb)

	stageTxt(t, zd, "a."+zone, "one")
	res := sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxCommit, ZoneName: zone, TxID: id}, true)
	if res.Err == nil || res.Applied {
		t.Errorf("the first commit: applied=%v err=%v, want the refusal", res.Applied, res.Err)
	}
	if zd.publishedSnapshot() != nil {
		t.Fatal("published unsigned")
	}

	// Still not signable: the repeat is accepted, and refused the same way.
	res = sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxCommit, ZoneName: zone, TxID: id}, true)
	if res.Err == nil || res.Applied {
		t.Errorf("the repeated commit without a policy: applied=%v err=%v, want the refusal", res.Applied, res.Err)
	}

	zd.mu.Lock()
	zd.DnssecPolicy = txTestPolicy()
	zd.mu.Unlock()
	res = sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxCommit, ZoneName: zone, TxID: id}, true)
	if res.Err != nil || !res.Applied {
		t.Fatalf("the repeated commit with a policy: applied=%v err=%v", res.Applied, res.Err)
	}
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("the repeated commit installed nothing")
	}
	// Nobody called SignZone on this zone. The publish that installs the first
	// snapshot put the whole zone in scope itself: keys, signatures, chain.
	if !served(zd, zone, dns.TypeDNSKEY) {
		t.Error("the first snapshot has no DNSKEY RRset")
	}
	unsigned, nsecs := unsignedRRsets(snap)
	if len(unsigned) > 0 {
		t.Errorf("unsigned RRsets in the first snapshot: %v", unsigned)
	}
	if nsecs == 0 {
		t.Error("the first snapshot has no NSEC chain")
	}
	if !zd.Ready {
		t.Error("the zone is not Ready")
	}
	if zd.HasError(FirstPublishError) {
		t.Error("the error outlived the first publish")
	}
	// Once published, the transaction is gone for good.
	if res := sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxCommit, ZoneName: zone, TxID: id}, true); res.Err == nil {
		t.Error("a commit after the first publish was accepted")
	}
}

// ---------------------------------------------------------------------------
// One serial: the producer's half of #653.

// secondaryDouble is what a secondary of the zone sees. It asks the zone's SOA
// over and over, the way a secondary that has been told about a zone does, and
// transfers every serial it has not seen. Queries go through QueryResponder and
// transfers through ZoneTransferOut, found by name in the zone registry, as
// the server does it.
type secondaryDouble struct {
	t    *testing.T
	zone string
	kdb  *KeyDB
	addr string

	mu        sync.Mutex
	rcodes    []int           // every change of the SOA query's rcode, in order
	transfers []transferred   // one per serial it could transfer
	refused   int             // transfers of an announced serial that were refused
	seen      map[uint32]bool // serials already transferred
}

type transferred struct {
	serial  uint32
	rrsets  map[string]bool // "owner/TYPE"
	covered map[string]bool // "owner/TYPE" with an RRSIG over it
}

func startSecondaryDouble(t *testing.T, kdb *KeyDB, zone string) *secondaryDouble {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	sd := &secondaryDouble{t: t, zone: zone, kdb: kdb, addr: ln.Addr().String(), seen: map[uint32]bool{}}

	srvCtx, srvCancel := context.WithCancel(context.Background())
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		refuse := func(rcode int) {
			m := new(dns.Msg)
			m.SetRcode(r, rcode)
			_ = w.WriteMsg(m)
		}
		if len(r.Question) != 1 {
			refuse(dns.RcodeFormatError)
			return
		}
		zd, ok := Zones.Get(zone)
		if !ok {
			refuse(dns.RcodeRefused) // not a zone of this server (yet)
			return
		}
		q := r.Question[0]
		if q.Qtype == dns.TypeAXFR {
			_, _ = zd.ZoneTransferOut(srvCtx, w, r, nil)
			return
		}
		msgo, err := edns0.ExtractFlagsAndEDNS0Options(r)
		if err != nil {
			refuse(dns.RcodeFormatError)
			return
		}
		_ = zd.QueryResponder(srvCtx, w, r, q.Name, q.Qtype, msgo, kdb, nil)
	})
	started := make(chan struct{})
	srv := &dns.Server{Listener: ln, Handler: mux, MsgAcceptFunc: MsgAcceptFunc,
		NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("the secondary double's server did not start")
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			sd.poll()
			time.Sleep(time.Millisecond)
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
		srvCancel()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	return sd
}

func (sd *secondaryDouble) poll() {
	m := new(dns.Msg)
	m.SetQuestion(sd.zone, dns.TypeSOA)
	c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, sd.addr)
	if err != nil {
		return
	}
	sd.mu.Lock()
	if len(sd.rcodes) == 0 || sd.rcodes[len(sd.rcodes)-1] != r.Rcode {
		sd.rcodes = append(sd.rcodes, r.Rcode)
	}
	sd.mu.Unlock()

	var serial uint32
	have := false
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			serial, have = soa.Serial, true
		}
	}
	if r.Rcode != dns.RcodeSuccess || !have {
		return
	}
	sd.mu.Lock()
	seen := sd.seen[serial]
	sd.mu.Unlock()
	if seen {
		return
	}

	// A serial it has not seen: transfer it, as a secondary does. Only then,
	// and not while the zone says SERVFAIL. The producer sets the zone's
	// transfer ACL after the zone is registered, as the real one does, and the
	// transfer path reads it without the zone's lock; a transfer attempted
	// during the set-up would be a data race that is not this test's subject.
	// That a transfer IS refused during the hold is pinned without concurrency
	// by TestTheFirstSnapshotOfASigningZoneIsSigned.
	req := new(dns.Msg)
	req.SetAxfr(sd.zone)
	ch, err := new(dns.Transfer).In(req, sd.addr)
	if err != nil {
		return
	}
	tr := transferred{rrsets: map[string]bool{}, covered: map[string]bool{}}
	failed := false
	for env := range ch {
		if env.Error != nil {
			failed = true
			continue
		}
		for _, rr := range env.RR {
			owner := core.CanonicalizeName(rr.Header().Name)
			switch v := rr.(type) {
			case *dns.RRSIG:
				tr.covered[owner+"/"+dns.TypeToString[v.TypeCovered]] = true
			case *dns.SOA:
				tr.serial = v.Serial
				tr.rrsets[owner+"/SOA"] = true
			default:
				tr.rrsets[owner+"/"+typeName(rr.Header().Rrtype)] = true
			}
		}
	}
	sd.mu.Lock()
	defer sd.mu.Unlock()
	if failed || len(tr.rrsets) == 0 {
		sd.refused++
		return
	}
	if !sd.seen[tr.serial] {
		sd.seen[tr.serial] = true
		sd.transfers = append(sd.transfers, tr)
	}
}

func typeName(rrtype uint16) string {
	if rrtype == core.TypeJWK {
		return "JWK"
	}
	if s, ok := dns.TypeToString[rrtype]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", rrtype)
}

func (sd *secondaryDouble) observed() (rcodes []int, transfers []transferred, refused int) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	return append([]int(nil), sd.rcodes...), append([]transferred(nil), sd.transfers...), sd.refused
}

// produceIdentityZone is shaped like the multi-provider agent's set-up of its
// identity zone, in its order and through the same joins: the zone is created
// held; signing, the notify targets and the transfer ACL are set afterwards;
// the zone is signed; each record is its own queued update; a KEY arrives from
// another writer; and the commit goes through the queue, behind the updates.
// The pauses stand in for the work the real producer does between records, a
// second in all in the case that was diagnosed.
func produceIdentityZone(t *testing.T, kdb *KeyDB, zone string) (*ZoneData, ZoneUpdateResult) {
	t.Helper()
	zd, id, err := kdb.CreateAutoZoneHeld(zone, nil, []string{"ns.identity.example."})
	if err != nil {
		t.Fatalf("CreateAutoZoneHeld: %v", err)
	}
	cleanupTxZone(t, zd)
	pause := func() { time.Sleep(15 * time.Millisecond) }
	pause()

	zd.mu.Lock()
	zd.Options[OptAllowUpdates] = true
	zd.Notify = []PeerConf{{Addr: "127.0.0.1:53", Key: NOKEY}}
	zd.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}}
	zd.Options[OptOnlineSigning] = true
	zd.DnssecPolicy = txTestPolicy()
	zd.mu.Unlock()
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	pause()

	host := "dns." + zone
	if err := zd.PublishUriRR("_dns._tcp."+zone, strings.TrimSuffix(zone, "."), "dns://{TARGET}:{PORT}/", 5399); err != nil {
		t.Fatalf("PublishUriRR: %v", err)
	}
	pause()
	for _, addr := range []string{"192.0.2.53", "2001:db8::53"} {
		if err := zd.PublishAddrRR(host, addr); err != nil {
			t.Fatalf("PublishAddrRR(%s): %v", addr, err)
		}
		pause()
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := zd.PublishJWKRR(host, &priv.PublicKey, "sig"); err != nil {
		t.Fatalf("PublishJWKRR: %v", err)
	}
	pause()
	if err := zd.PublishSvcbRR(host, 5399, []dns.SVCBKeyValue{
		&dns.SVCBPort{Port: 5399},
		&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("192.0.2.53")}},
	}); err != nil {
		t.Fatalf("PublishSvcbRR: %v", err)
	}
	pause()
	// Another writer, from its own goroutine in the real thing: the SIG(0) KEY.
	sendTx(t, kdb, UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zone,
		InternalUpdate: true,
		Actions: []dns.RR{txTestRR(t, zone+
			" 3600 IN KEY 512 3 15 XeXZZpzuRlXaHY2QDDIDxTNOLTFHtBzQ1pMU0aLVnLQ=")},
	}, false)
	pause()

	res := sendTx(t, kdb, UpdateRequest{Cmd: UpdateCmdTxCommit, ZoneName: zone, TxID: id}, true)
	return zd, res
}

// One serial. A secondary of a zone created held sees SERVFAIL, then one
// transfer of the complete, signed zone. Without the transaction it sees the
// zone as SOA and NS first, an authoritative denial of everything the zone is
// about to hold, and then a serial per record.
func TestASecondarySeesOneSerialOfAnIdentityZone(t *testing.T) {
	const zone = "identity.tx.example."
	notifies := withNotifyQ(t, 32)
	kdb := newTestKeyDB(t)
	startTxUpdater(t, kdb)
	sd := startSecondaryDouble(t, kdb, zone)

	zd, res := produceIdentityZone(t, kdb, zone)
	if res.Err != nil || !res.Applied {
		t.Errorf("the commit's Resp: applied=%v err=%v", res.Applied, res.Err)
	}
	waitFor(t, 5*time.Second, "the secondary to transfer the zone", func() bool {
		_, transfers, _ := sd.observed()
		return len(transfers) > 0 && zd.publishedSnapshot() != nil &&
			transfers[len(transfers)-1].serial == zd.publishedSnapshot().Serial
	})
	time.Sleep(50 * time.Millisecond)
	rcodes, transfers, refused := sd.observed()

	var rcodeNames []string
	for _, rc := range rcodes {
		rcodeNames = append(rcodeNames, dns.RcodeToString[rc])
	}
	t.Logf("the secondary saw rcodes %v, was refused %d transfer(s), and transferred %d serial(s)",
		rcodeNames, refused, len(transfers))
	for _, tr := range transfers {
		var sets []string
		for k := range tr.rrsets {
			sets = append(sets, strings.TrimSuffix(strings.TrimSuffix(k, zone), "."))
		}
		sort.Strings(sets)
		t.Logf("  serial %d: %d RRsets %v", tr.serial, len(tr.rrsets), sets)
	}

	// SERVFAIL until the commit: not a denial a resolver would cache, and what
	// a secondary says for a zone it has configured and not loaded.
	sawServfail := false
	for _, rc := range rcodes {
		if rc == dns.RcodeServerFailure {
			sawServfail = true
		}
	}
	if !sawServfail {
		t.Error("the secondary never saw SERVFAIL: the zone was answerable before its first content was complete")
	}
	if len(transfers) != 1 {
		t.Fatalf("the secondary transferred %d serials, want one", len(transfers))
	}
	first := transfers[0]
	c := core.CanonicalizeName
	for _, want := range []string{
		c(zone) + "/SOA", c(zone) + "/NS", c(zone) + "/DNSKEY", c(zone) + "/KEY",
		c("_dns._tcp."+zone) + "/URI",
		c("dns."+zone) + "/A", c("dns."+zone) + "/AAAA", c("dns."+zone) + "/JWK", c("dns."+zone) + "/SVCB",
	} {
		if !first.rrsets[want] {
			t.Errorf("the one serial lacks %s", want)
		}
		if !first.covered[want] {
			t.Errorf("the one serial has no RRSIG over %s", want)
		}
	}
	if !first.rrsets[c(zone)+"/NSEC"] || !first.covered[c(zone)+"/NSEC"] {
		t.Error("the one serial has no signed NSEC at the apex")
	}
	if n := drainNotifies(notifies); n != 1 {
		t.Errorf("%d NOTIFYs, want one", n)
	}
}
