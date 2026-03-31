/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Unit tests for agent router CLI commands.
 */

package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestAgentRouterCommandStructure(t *testing.T) {
	// Verify main router command exists
	if agentRouterCmd == nil {
		t.Fatal("agentRouterCmd is nil")
	}

	if agentRouterCmd.Use != "router" {
		t.Errorf("Expected Use='router', got %q", agentRouterCmd.Use)
	}

	// Verify subcommands are registered
	expectedSubcommands := []string{
		"list",
		"describe",
		"metrics",
		"walk",
		"reset",
	}

	subcommands := agentRouterCmd.Commands()
	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("Expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
	}

	// Verify each expected subcommand exists
	subcommandMap := make(map[string]*cobra.Command)
	for _, cmd := range subcommands {
		subcommandMap[cmd.Name()] = cmd
	}

	for _, name := range expectedSubcommands {
		if _, exists := subcommandMap[name]; !exists {
			t.Errorf("Missing expected subcommand: %s", name)
		}
	}
}

func TestAgentRouterListCommand(t *testing.T) {
	if agentRouterListCmd == nil {
		t.Fatal("agentRouterListCmd is nil")
	}

	if agentRouterListCmd.Use != "list" {
		t.Errorf("Expected Use='list', got %q", agentRouterListCmd.Use)
	}

	if agentRouterListCmd.Short == "" {
		t.Error("Short description is empty")
	}

	if agentRouterListCmd.Long == "" {
		t.Error("Long description is empty")
	}

	if agentRouterListCmd.Run == nil {
		t.Error("Run function is nil")
	}
}

func TestAgentRouterDescribeCommand(t *testing.T) {
	if agentRouterDescribeCmd == nil {
		t.Fatal("agentRouterDescribeCmd is nil")
	}

	if agentRouterDescribeCmd.Use != "describe" {
		t.Errorf("Expected Use='describe', got %q", agentRouterDescribeCmd.Use)
	}

	if agentRouterDescribeCmd.Run == nil {
		t.Error("Run function is nil")
	}
}

func TestAgentRouterMetricsCommand(t *testing.T) {
	if agentRouterMetricsCmd == nil {
		t.Fatal("agentRouterMetricsCmd is nil")
	}

	if agentRouterMetricsCmd.Use != "metrics" {
		t.Errorf("Expected Use='metrics', got %q", agentRouterMetricsCmd.Use)
	}

	if agentRouterMetricsCmd.Run == nil {
		t.Error("Run function is nil")
	}
}

func TestAgentRouterWalkCommand(t *testing.T) {
	if agentRouterWalkCmd == nil {
		t.Fatal("agentRouterWalkCmd is nil")
	}

	if agentRouterWalkCmd.Use != "walk" {
		t.Errorf("Expected Use='walk', got %q", agentRouterWalkCmd.Use)
	}

	if agentRouterWalkCmd.Run == nil {
		t.Error("Run function is nil")
	}
}

func TestAgentRouterResetCommand(t *testing.T) {
	if agentRouterResetCmd == nil {
		t.Fatal("agentRouterResetCmd is nil")
	}

	if agentRouterResetCmd.Use != "reset" {
		t.Errorf("Expected Use='reset', got %q", agentRouterResetCmd.Use)
	}

	if agentRouterResetCmd.Run == nil {
		t.Error("Run function is nil")
	}
}

func TestAgentRouterCommandsAddedToParent(t *testing.T) {
	// Verify router command is added to agent command
	if AgentCmd == nil {
		t.Fatal("AgentCmd is nil")
	}

	commands := AgentCmd.Commands()
	found := false
	for _, cmd := range commands {
		if cmd.Name() == "router" {
			found = true
			break
		}
	}

	if !found {
		t.Error("router command not added to agent command")
	}
}

func TestCommandExamples(t *testing.T) {
	commands := []*cobra.Command{
		agentRouterListCmd,
		agentRouterDescribeCmd,
		agentRouterMetricsCmd,
		agentRouterWalkCmd,
		agentRouterResetCmd,
	}

	for _, cmd := range commands {
		// All commands should have a Long description with an example
		if cmd.Long == "" {
			t.Errorf("Command %s missing Long description", cmd.Name())
		}
	}
}
