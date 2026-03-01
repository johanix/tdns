/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CHUNK query handler for query-mode CHUNK. Registered with RegisterQueryHandler(core.TypeCHUNK, ...).
 * Supports both manifest-based chunk arrays (sequence-numbered qnames) and legacy single-blob lookups.
 *
 * Qname format for chunk arrays: <sequence>.<receiver>.<distid>.<sender>.
 * If the first label is numeric, it's treated as a sequence number and stripped to form the base qname.
 */

package tdns

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// RegisterChunkQueryHandler registers a query handler for CHUNK that serves payloads from the store.
// Should be called when running as agent with chunk_mode "query". store must not be nil.
func RegisterChunkQueryHandler(store ChunkPayloadStore) error {
	if store == nil {
		return fmt.Errorf("chunk payload store cannot be nil")
	}
	return RegisterQueryHandler(core.TypeCHUNK, func(ctx context.Context, req *DnsQueryRequest) error {
		return chunkQueryHandler(ctx, req, store)
	})
}

func chunkQueryHandler(ctx context.Context, req *DnsQueryRequest, store ChunkPayloadStore) error {
	if req.Qtype != core.TypeCHUNK {
		return ErrNotHandled
	}
	qname := dns.Fqdn(req.Qname)

	// Try sequence-numbered lookup: if the first label is numeric, parse it as a sequence number
	// and look up the chunk array under the base qname (remaining labels).
	labels := dns.SplitDomainName(qname)
	if len(labels) >= 4 {
		if seq, err := strconv.ParseUint(labels[0], 10, 16); err == nil {
			baseQname := dns.Fqdn(strings.Join(labels[1:], "."))
			if chunk, ok := store.GetChunk(baseQname, uint16(seq)); ok {
				if Globals.Debug {
					log.Printf("ChunkQueryHandler: qname=%q seq=%d base=%q datalen=%d",
						qname, seq, baseQname, len(chunk.Data))
				}
				return serveChunkRR(req, qname, chunk)
			}
		}
	}

	// Fall back to legacy single-blob lookup
	payload, format, ok := store.Get(qname)
	if !ok {
		return ErrNotHandled
	}

	if Globals.Debug {
		log.Printf("ChunkQueryHandler: legacy qname=%q len=%d format=%d",
			qname, len(payload), format)
	}

	chunk := &core.CHUNK{
		Format:     format,
		HMACLen:    0,
		HMAC:       nil,
		Sequence:   0,
		Total:      1,
		DataLength: uint16(len(payload)),
		Data:       payload,
	}
	return serveChunkRR(req, qname, chunk)
}

// serveChunkRR builds and sends a DNS response containing a single CHUNK RR.
func serveChunkRR(req *DnsQueryRequest, qname string, chunk *core.CHUNK) error {
	chunkRR := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: core.TypeCHUNK,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Data: chunk,
	}
	m := new(dns.Msg)
	m.SetReply(req.Msg)
	m.Authoritative = true
	m.Answer = append(m.Answer, chunkRR)
	if err := req.ResponseWriter.WriteMsg(m); err != nil {
		log.Printf("ChunkQueryHandler: failed to write response for %s: %v", qname, err)
		return err
	}
	if Globals.Debug {
		log.Printf("ChunkQueryHandler: served CHUNK for qname=%q", qname)
	}
	return nil
}
