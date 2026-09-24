/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/miekg/dns"
)

// cdsKind is what a CDS RRset asks of the parent.
type cdsKind uint8

const (
	// cdsUpdate: no algorithm-0 record; the DS RRset the CDS describes.
	cdsUpdate cdsKind = iota
	// cdsDelete: the RFC 8078 §4 delete, remove every DS.
	cdsDelete
	// cdsMalformed: an algorithm-0 record in any other shape. RFC 7344 §4.1:
	// a CDS that breaks the rules is ignored.
	cdsMalformed
)

func (k cdsKind) String() string {
	switch k {
	case cdsUpdate:
		return "update"
	case cdsDelete:
		return "delete"
	case cdsMalformed:
		return "malformed"
	}
	return fmt.Sprintf("cdsKind(%d)", uint8(k))
}

// deleteDigest is the digest of the RFC 8078 §4 delete CDS as it is on the
// wire: one zero byte. The RFC writes the record "0 0 0 0"; unpacked, the DNS
// library shows the digest as "00".
var deleteDigest = []byte{0}

// classifyCDS reads a CDS RRset the way RFC 8078 §4 and RFC 7344 §4.1 do
// (#755). The delete is exactly one record, `0 0 0 00`: key tag 0, algorithm
// 0, digest type 0, and a digest of one zero byte. Any other set holding an
// algorithm-0 record breaks the rules -- a delete beside real records, two
// deletes, an algorithm-0 record with a real key tag, digest type or digest --
// and is malformed, which the caller must ignore rather than act on. Reading
// "any algorithm-0 record" as the delete, as before, took a secure child
// insecure on a mixed set. reason says why a set is malformed.
func classifyCDS(rrs []dns.RR) (kind cdsKind, reason string) {
	var zero []*dns.CDS
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CDS); ok && c.Algorithm == 0 {
			zero = append(zero, c)
		}
	}
	switch {
	case len(zero) == 0:
		return cdsUpdate, ""
	case len(rrs) > 1 && len(zero) == len(rrs):
		return cdsMalformed, fmt.Sprintf("%d algorithm-0 records; the RFC 8078 delete is exactly one", len(zero))
	case len(rrs) > 1:
		return cdsMalformed, "an algorithm-0 record alongside other CDS records; the RFC 8078 delete is exactly one record"
	}
	c := zero[0]
	digest, err := hex.DecodeString(c.Digest)
	switch {
	case c.KeyTag != 0:
		return cdsMalformed, fmt.Sprintf("an algorithm-0 record with key tag %d; the RFC 8078 delete is 0 0 0 00", c.KeyTag)
	case c.DigestType != 0:
		return cdsMalformed, fmt.Sprintf("an algorithm-0 record with digest type %d; the RFC 8078 delete is 0 0 0 00", c.DigestType)
	case err != nil || !bytes.Equal(digest, deleteDigest):
		return cdsMalformed, fmt.Sprintf("an algorithm-0 record with digest %q; the RFC 8078 delete is 0 0 0 00", c.Digest)
	}
	return cdsDelete, ""
}
