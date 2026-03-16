/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * API handlers for DNS message router introspection.
 */

package tdns

import (
	"fmt"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
)

// handleRouterList returns a list of all registered handlers grouped by message type.
func handleRouterList(router *transport.DNSMessageRouter) *AgentMgmtResponse {
	resp := &AgentMgmtResponse{
		Time: time.Now(),
	}

	if router == nil {
		resp.Error = true
		resp.ErrorMsg = "Router not initialized"
		return resp
	}

	handlers := router.List()
	if len(handlers) == 0 {
		resp.Msg = "No handlers registered"
		return resp
	}

	// Convert to a format suitable for JSON serialization
	handlerData := make(map[string][]map[string]interface{})
	for msgType, regs := range handlers {
		handlerList := make([]map[string]interface{}, len(regs))
		for i, reg := range regs {
			calls := reg.CallCount.Load()
			errors := reg.ErrorCount.Load()
			latency := time.Duration(reg.TotalLatency.Load())
			avgLatency := time.Duration(0)
			if calls > 0 {
				avgLatency = latency / time.Duration(calls)
			}

			handlerList[i] = map[string]interface{}{
				"name":          reg.Name,
				"message_type":  string(reg.MessageType),
				"priority":      reg.Priority,
				"description":   reg.Description,
				"registered":    reg.Registered.Format(time.RFC3339),
				"call_count":    calls,
				"error_count":   errors,
				"total_latency": latency.String(),
				"avg_latency":   avgLatency.String(),
			}
		}
		handlerData[string(msgType)] = handlerList
	}

	resp.Data = map[string]interface{}{
		"handlers": handlerData,
	}
	resp.Msg = fmt.Sprintf("Found %d message types with handlers", len(handlers))

	return resp
}

// handleRouterDescribe returns a detailed description of the router state.
func handleRouterDescribe(router *transport.DNSMessageRouter) *AgentMgmtResponse {
	resp := &AgentMgmtResponse{
		Time: time.Now(),
	}

	if router == nil {
		resp.Error = true
		resp.ErrorMsg = "Router not initialized"
		return resp
	}

	description := router.Describe()
	resp.Data = description
	resp.Msg = "Router description retrieved"

	return resp
}

// handleRouterMetrics returns router-level metrics.
func handleRouterMetrics(router *transport.DNSMessageRouter) *AgentMgmtResponse {
	resp := &AgentMgmtResponse{
		Time: time.Now(),
	}

	if router == nil {
		resp.Error = true
		resp.ErrorMsg = "Router not initialized"
		return resp
	}

	metrics := router.GetMetrics()

	// Convert unhandled types map
	unhandledTypes := make(map[string]uint64)
	for msgType, count := range metrics.UnhandledTypes {
		unhandledTypes[string(msgType)] = count
	}

	resp.Data = map[string]interface{}{
		"total_messages":    metrics.TotalMessages,
		"unknown_messages":  metrics.UnknownMessages,
		"middleware_errors": metrics.MiddlewareErrors,
		"handler_errors":    metrics.HandlerErrors,
		"unhandled_types":   unhandledTypes,
	}
	resp.Msg = "Router metrics retrieved"

	return resp
}

// handleRouterWalk walks all handlers and returns them in a list.
func handleRouterWalk(router *transport.DNSMessageRouter) *AgentMgmtResponse {
	resp := &AgentMgmtResponse{
		Time: time.Now(),
	}

	if router == nil {
		resp.Error = true
		resp.ErrorMsg = "Router not initialized"
		return resp
	}

	var walkResults []map[string]interface{}

	err := router.Walk(func(reg *transport.HandlerRegistration) error {
		calls := reg.CallCount.Load()
		errors := reg.ErrorCount.Load()
		latency := time.Duration(reg.TotalLatency.Load())
		avgLatency := time.Duration(0)
		if calls > 0 {
			avgLatency = latency / time.Duration(calls)
		}

		walkResults = append(walkResults, map[string]interface{}{
			"name":          reg.Name,
			"message_type":  string(reg.MessageType),
			"priority":      reg.Priority,
			"description":   reg.Description,
			"registered":    reg.Registered.Format(time.RFC3339),
			"call_count":    calls,
			"error_count":   errors,
			"total_latency": latency.String(),
			"avg_latency":   avgLatency.String(),
		})
		return nil
	})

	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("Walk failed: %v", err)
		return resp
	}

	resp.Data = walkResults
	resp.Msg = fmt.Sprintf("Walked %d handlers", len(walkResults))

	return resp
}

// handleRouterReset resets all router metrics.
func handleRouterReset(router *transport.DNSMessageRouter) *AgentMgmtResponse {
	resp := &AgentMgmtResponse{
		Time: time.Now(),
	}

	if router == nil {
		resp.Error = true
		resp.ErrorMsg = "Router not initialized"
		return resp
	}

	router.Reset()
	lgApi.Info("router metrics reset via API")

	resp.Msg = "Router metrics reset successfully"
	return resp
}

// AddRouterCommandsToSwitch adds router command handling to the agent API switch statement.
// This should be called from APIagent handler to add the router command cases.
//
// Example usage in apihandler_agent.go:
//
//	switch amp.Command {
//	// ... existing cases ...
//	case "router-list":
//		if conf.Internal.TransportManager == nil || conf.Internal.TransportManager.Router == nil {
//			resp.Error = true
//			resp.ErrorMsg = "Router not available (DNS transport not configured)"
//			return
//		}
//		routerResp := handleRouterList(conf.Internal.TransportManager.Router)
//		resp = *routerResp
//	// ... add other router cases ...
//	}
func AddRouterCommandsToSwitch() {
	// This is a documentation function - the actual switch cases need to be added
	// manually to apihandler_agent.go. This function serves as a guide.
	lgApi.Info("router command handlers available: router-list, router-describe, router-metrics, router-walk, router-reset")
}
