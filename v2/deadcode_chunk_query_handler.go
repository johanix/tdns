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
				lgHandler.Debug("serving chunk", "qname", qname, "seq", seq, "base", baseQname, "dataLen", len(chunk.Data))
				return serveChunkRR(req, qname, chunk)
			}
		}
	}

	// Fall back to legacy single-blob lookup
	payload, format, ok := store.Get(qname)
	if !ok {
		return ErrNotHandled
	}

	lgHandler.Debug("serving legacy chunk", "qname", qname, "len", len(payload), "format", format)

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
		lgHandler.Error("failed to write chunk response", "qname", qname, "error", err)
		return err
	}
	lgHandler.Debug("served CHUNK", "qname", qname)
	return nil
}
