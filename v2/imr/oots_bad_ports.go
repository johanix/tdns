/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"github.com/johanix/tdns/v2/cache"
)

// The port policy of a transport signal: a record may send a transport to
// any port, at the nameserver itself or at a target, except a port on the
// list below. A browser refuses the same ports for the port of an HTTPS
// record. Without the list, a zone operator could make the resolver send DNS
// to the port of any service on any host it can reach: SSH, SMTP and the like.

// signalBadPorts are the "bad ports" of the WHATWG Fetch Standard, section
// 2.9 "Port blocking" (https://fetch.spec.whatwg.org/#port-blocking), as of
// November 2026, less 53. Port 0 is left out too: in SVCB it is no port key.
var signalBadPorts = map[uint16]bool{
	1: true, 7: true, 9: true, 11: true, 13: true, 15: true, 17: true, 19: true,
	20: true, 21: true, 22: true, 23: true, 25: true, 37: true, 42: true, 43: true,
	69: true, 77: true, 79: true, 87: true, 95: true, 101: true, 102: true, 103: true,
	104: true, 109: true, 110: true, 111: true, 113: true, 115: true, 117: true, 119: true,
	123: true, 135: true, 137: true, 139: true, 143: true, 161: true, 179: true, 389: true,
	427: true, 465: true, 512: true, 513: true, 514: true, 515: true, 526: true, 530: true,
	531: true, 532: true, 540: true, 548: true, 554: true, 556: true, 563: true, 587: true,
	601: true, 636: true, 989: true, 990: true, 993: true, 995: true, 1719: true, 1720: true,
	1723: true, 2049: true, 3659: true, 4045: true, 4190: true, 5060: true, 5061: true, 6000: true,
	6566: true, 6665: true, 6666: true, 6667: true, 6668: true, 6669: true, 6679: true, 6697: true,
	10080: true,
}

// signalPortRefused reports whether a transport signal may not use port p.
// The transports' own default ports, 53, 853 and 443, are never refused,
// whatever the list holds; nor is 0, no port key.
func signalPortRefused(p uint16) bool {
	switch p {
	case 0, 53, 443, 853:
		return false
	}
	return signalBadPorts[p]
}

// withoutBadPorts is recs with each record whose port a signal may not use
// (signalPortRefused) taken as one about the nameserver itself on the
// default ports: as if its TargetName were "." and it had no port key. Each
// such record is logged at debug level. recs itself is not changed. It runs
// on records already honoured (honouredRecords): a record with a target that
// the path does not allow stays ignored whole, and does not come back as one
// about the nameserver itself.
func (imr *Imr) withoutBadPorts(server *cache.AuthServer, recs []ootsRecord) []ootsRecord {
	var out []ootsRecord
	for i, rec := range recs {
		if !signalPortRefused(rec.port) {
			if out != nil {
				out = append(out, rec)
			}
			continue
		}
		if out == nil {
			out = make([]ootsRecord, i, len(recs))
			copy(out, recs[:i])
		}
		imr.lgDns().Debug("transport signal: a port on the bad-port list refused; the nameserver itself on the default port",
			"servername", server.Name, "port", rec.port, "target", rec.target, "transports", MarshalTransport(rec.raw))
		rec.port, rec.target = 0, ""
		out = append(out, rec)
	}
	if out == nil {
		return recs
	}
	return out
}
