/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Initialization helpers for the transport package.
 * These functions help integrate the transport package with the main tdns package.
 */

package transport

/*
INTEGRATION GUIDE

To integrate the CHUNK NOTIFY handler with tdns, add the following code to your
agent initialization (e.g., in tdns-agent/main.go or agent setup):

	import (
		"github.com/johanix/tdns/v2"
		"github.com/johanix/tdns/v2/agent/transport"
		"github.com/johanix/tdns/v2/core"
	)

	func setupDNSTransport(controlZone, localID string) (*transport.DNSTransport, *transport.ChunkNotifyHandler) {
		// Create DNS transport
		dnsTransport := transport.NewDNSTransport(&transport.DNSTransportConfig{
			LocalID:     localID,
			ControlZone: controlZone,
			Timeout:     5 * time.Second,
		})

		// Create CHUNK NOTIFY handler
		chunkHandler := transport.NewChunkNotifyHandler(controlZone, localID, dnsTransport)

		// Register the handler with tdns
		// This creates an adapter from the generic handler to tdns.NotifyHandlerFunc
		tdns.RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *tdns.DnsNotifyRequest) error {
			return chunkHandler.HandleChunkNotify(ctx, req.Qname, req.Msg, req.ResponseWriter)
		})

		// Start a goroutine to process incoming messages and route to hsyncengine
		go func() {
			for msg := range chunkHandler.IncomingChan {
				// Route to hsyncengine based on message type
				processIncomingDNSMessage(msg)
			}
		}()

		return dnsTransport, chunkHandler
	}

	func processIncomingDNSMessage(msg *transport.IncomingMessage) {
		switch msg.Type {
		case "hello":
			// Parse and handle hello
			payload, _ := transport.ParseHelloPayload(msg.Payload)
			// ... handle hello from remote agent
		case "beat":
			// Parse and handle beat
			payload, _ := transport.ParseBeatPayload(msg.Payload)
			// ... handle heartbeat
		case "sync":
			// Parse and handle sync
			payload, _ := transport.ParseSyncPayload(msg.Payload)
			// ... handle sync request, send confirmation
		case "relocate":
			// Parse and handle relocate
			payload, _ := transport.ParseRelocatePayload(msg.Payload)
			// ... handle address relocation
		}
	}

TRANSPORT SELECTION

The hsyncengine should select transport based on peer configuration:

	func (engine *HsyncEngine) selectTransport(peer *transport.Peer) transport.Transport {
		// Check peer's preferred transport
		switch peer.PreferredTransport {
		case "DNS":
			if engine.dnsTransport != nil {
				return engine.dnsTransport
			}
		case "API":
			if engine.apiTransport != nil {
				return engine.apiTransport
			}
		}

		// Default: try API first, then DNS
		if engine.apiTransport != nil && peer.APIEndpoint != "" {
			return engine.apiTransport
		}
		if engine.dnsTransport != nil && peer.CurrentAddress() != nil {
			return engine.dnsTransport
		}

		return nil
	}

FALLBACK LOGIC

For robust communication, implement transport fallback:

	func (engine *HsyncEngine) sendWithFallback(ctx context.Context, peer *transport.Peer, req *transport.SyncRequest) (*transport.SyncResponse, error) {
		// Try preferred transport first
		t := engine.selectTransport(peer)
		if t != nil {
			resp, err := t.Sync(ctx, peer, req)
			if err == nil {
				return resp, nil
			}
			log.Printf("Primary transport %s failed: %v, trying fallback", t.Name(), err)
		}

		// Try alternative transport
		if t == engine.apiTransport && engine.dnsTransport != nil {
			return engine.dnsTransport.Sync(ctx, peer, req)
		}
		if t == engine.dnsTransport && engine.apiTransport != nil {
			return engine.apiTransport.Sync(ctx, peer, req)
		}

		return nil, fmt.Errorf("all transports failed")
	}
*/
