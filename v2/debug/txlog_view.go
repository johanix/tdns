/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"encoding/json"
	"fmt"

	tdns "github.com/johanix/tdns/v2"
)

// Tool-local mirror of the zone-txlog wire types from the
// feature/zone-snapshot-correctness branch (v2/zone_snapshot.go there). The
// mirror is deliberate (design doc §3): this branch must not touch any file
// the snapshot branch modifies, and decoding into our own types is what makes
// the tool tolerant of servers that predate (or postdate) the txlog API.
//
// Faithful to the branch as of commit 5537a9e:
//
//	type PendingChangesView struct {
//	    PublishedSerial uint32                   `json:"published_serial"`
//	    PublishQueued   bool                     `json:"publish_queued"`
//	    Added           []string                 `json:"added,omitempty"`
//	    Replaced        []PendingOwnerChangeJSON `json:"replaced,omitempty"`
//	    Deleted         []PendingOwnerChangeJSON `json:"deleted,omitempty"`
//	}
type TxlogView struct {
	PublishedSerial uint32              `json:"published_serial"`
	PublishQueued   bool                `json:"publish_queued"`
	Added           []string            `json:"added,omitempty"`
	Replaced        []TxlogOwnerChange  `json:"replaced,omitempty"`
	Deleted         []TxlogOwnerChange  `json:"deleted,omitempty"`
}

type TxlogOwnerChange struct {
	Owner     string   `json:"owner"`
	RRtypes   []uint16 `json:"rrtypes"`
	TypeNames []string `json:"type_names,omitempty"`
}

// txlogResp mirrors just the DebugResponse fields the tool reads.
type txlogResp struct {
	Error     bool
	ErrorMsg  string
	Msg       string
	ZoneTxlog *TxlogView
}

// FetchTxlog retrieves the pending-changes view for zone. A server without
// the capability returns a structured unknown-command error → (nil, absent
// error); callers gate on the capability matrix so this is normally not hit.
func FetchTxlog(ctx context.Context, api *tdns.ApiClient, zone string) (*TxlogView, error) {
	status, buf, err := api.RequestNGWithContext(ctx, "POST", "/debug",
		tdns.DebugPost{Command: "zone-txlog", Zone: zone}, false)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("zone-txlog: http status %d", status)
	}
	var tr txlogResp
	if err := json.Unmarshal(buf, &tr); err != nil {
		return nil, fmt.Errorf("zone-txlog: bad response: %v", err)
	}
	if tr.Error {
		return nil, fmt.Errorf("zone-txlog: %s", tr.ErrorMsg)
	}
	return tr.ZoneTxlog, nil
}
