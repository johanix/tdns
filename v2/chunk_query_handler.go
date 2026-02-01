/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CHUNK query handler for query-mode CHUNK. Registered with RegisterQueryHandler(core.TypeCHUNK, ...).
 * When chunk_mode is "query", the agent stores payload by qname and sends NOTIFY without EDNS0;
 * the combiner then queries the agent for qname CHUNK. This handler answers those queries
 * by looking up the payload in the store and returning it as a CHUNK RR.
 *
 * For potential reuse: tdns-kdc has a CHUNK query handler (e.g. KDC DNS handler for CHUNK type)
 * that serves distribution chunks by qname; comparing with that implementation may allow
 * sharing store semantics or response-building logic if both codebases are available.
 */

package tdns

import (
	"context"
	"fmt"
	"log"

	core "github.com/johanix/tdns/v2/core"
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
	// Normalize to FQDN so lookup matches what we store (e.g. "xxx.agent" and "xxx.agent." hit same entry)
	qname := dns.Fqdn(req.Qname)
	payload, format, ok := store.Get(qname)
	if !ok {
		return ErrNotHandled
	}

	if Globals.Debug {
		log.Printf("ChunkQueryHandler: qname=%q len=%d format=%d (JSON=%d JWT=%d)",
			qname, len(payload), format, core.FormatJSON, core.FormatJWT)
	}

	// Build CHUNK RR: single payload as Sequence=0, Total=1 (opaque payload record)
	chunk := &core.CHUNK{
		Format:     format,
		HMACLen:    0,
		HMAC:       nil,
		Sequence:   0,
		Total:      1,
		DataLength: uint16(len(payload)),
		Data:       payload,
	}
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
