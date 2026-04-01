/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * tdns-cli auth peer ... — commands for multi-provider peer management on tdns-auth.
 * list: show known peers.
 * ping: DNS CHUNK ping from signer to agent (or specific peer).
 * status: show multi-provider status.
 */

package cli

import (
	"encoding/json"
	"fmt"
	"log"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// authPeerCmd is the prefix for auth commands regarding peers.
var authPeerCmd = &cobra.Command{
	Use:   "peer",
	Short: "Multi-provider peer management commands",
	Long:  `Commands for managing multi-provider DNSSEC peer relationships (list, ping, status).`,
}

var authPeerPingID string

var authPeerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all known peers",
	Long: `Show all peers known to this signer (registered in the PeerRegistry).

Example:
  tdns-cliv2 auth peer list
  tdns-cliv2 auth peer list --verbose`,
	Run: func(cmd *cobra.Command, args []string) {
		ListDistribPeers(cmd, "auth")
	},
}

var authPeerPingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Ping a peer via DNS CHUNK",
	Long: `Send a DNS CHUNK ping to a peer and report the result.
By default, pings the configured agent. Use --id to target a specific peer.

Examples:
  tdns-cliv2 auth peer ping
  tdns-cliv2 auth peer ping --id agent.alpha.dnslab.`,
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := SendAuthPeerCmd(tdns.AuthPeerPost{
			Command: "peer-ping",
			PeerID:  authPeerPingID,
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp.Error {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", resp.ErrorMsg)
			return
		}
		fmt.Println(resp.Msg)
	},
}

var authPeerStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show multi-provider status",
	Long: `Show the current multi-provider configuration and peer status.

Example:
  tdns-cliv2 auth peer status`,
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := SendAuthPeerCmd(tdns.AuthPeerPost{
			Command: "status",
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp.Error {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", resp.ErrorMsg)
			return
		}
		fmt.Println(resp.Msg)
	},
}

func init() {
	authPeerCmd.AddCommand(authPeerListCmd)
	authPeerCmd.AddCommand(authPeerPingCmd)
	authPeerCmd.AddCommand(authPeerStatusCmd)
	AuthCmd.AddCommand(authPeerCmd)

	authPeerListCmd.Flags().Bool("verbose", false, "Show detailed per-peer statistics")
	authPeerPingCmd.Flags().StringVar(&authPeerPingID, "id", "", "Identity of the peer to ping (default: configured agent)")
}

// SendAuthPeerCmd sends a peer command to the auth server's /auth/peer endpoint.
func SendAuthPeerCmd(req tdns.AuthPeerPost) (*tdns.AuthPeerResponse, error) {
	api, err := GetApiClient("auth", true)
	if err != nil {
		return nil, fmt.Errorf("error getting API client: %w", err)
	}

	status, buf, err := api.RequestNG("POST", "/auth/peer", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if status != 200 {
		return nil, fmt.Errorf("API request to %s/auth/peer returned HTTP %d: %s",
			api.BaseUrl, status, string(buf))
	}

	var result tdns.AuthPeerResponse
	if err := json.Unmarshal(buf, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response from %s/auth/peer: %w",
			api.BaseUrl, err)
	}

	return &result, nil
}
