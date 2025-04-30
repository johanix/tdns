package cmd

import (
	"fmt"
	"strings"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"
)

// CommandNode represents a node in our command tree
type CommandNode struct {
	Name        string                  // Command name
	Command     *cobra.Command          // Reference to original Cobra command
	SubCommands map[string]*CommandNode // Child commands
	Parent      *CommandNode            // Parent command (nil for root)
	Args        []string                // Expected arguments from Use field
	Guide       string                  // Guide text for this command
}

// BuildCommandTree creates a tree structure from Cobra commands
func BuildCommandTree(cmd *cobra.Command, parent *CommandNode) *CommandNode {
	// Parse the Use field to get command name and args
	parts := strings.Fields(cmd.Use)
	name := parts[0]
	args := parts[1:]

	guide := ""
	if cmd.Annotations != nil {
		guide = cmd.Annotations["guide"]
	}

	node := &CommandNode{
		Name:        name,
		Command:     cmd,
		SubCommands: make(map[string]*CommandNode),
		Parent:      parent,
		Args:        args,
		Guide:       guide,
	}

	// Process all subcommands
	for _, subCmd := range cmd.Commands() {
		// Skip help command and hidden commands
		switch {
		case subCmd.Name() == "help":
			continue
		case subCmd.Name() == "completion":
			continue
		case subCmd.Hidden:
			continue
		}
		if subCmd.Name() == "help" || subCmd.Hidden {
			continue
		}
		node.SubCommands[subCmd.Name()] = BuildCommandTree(subCmd, node)
	}

	return node
}

// Debug function to print the tree structure
func (n *CommandNode) DebugPrint(indent string) {
	fmt.Printf("%sCommand: %s\n", indent, n.Name)
	if len(n.Args) > 0 {
		fmt.Printf("%s  Args: %v\n", indent, n.Args)
	}
	if n.Guide != "" {
		fmt.Printf("%s  Guide: %s\n", indent, n.Guide)
	}
	for _, sub := range n.SubCommands {
		sub.DebugPrint(indent + "  ")
	}
}

// Global reference to our command tree
var commandTree *CommandNode

func startReadlineMode() {
	// Build the command tree
	commandTree = BuildCommandTree(cmdRoot, nil)

	// Debug: Print the tree
	fmt.Println("Command Tree Structure:")
	commandTree.DebugPrint("")

	rl, err := readline.New("tdns> ")
	if err != nil {
		fmt.Printf("Error initializing readline: %v\n", err)
		return
	}
	defer rl.Close()

	// Basic readline loop
	for {
		line, err := rl.Readline()
		if err != nil { // io.EOF, readline.ErrInterrupt
			break
		}

		line = strings.TrimSpace(line)
		if line == "exit" || line == "quit" {
			break
		}

		// Execute command via Cobra
		if line != "" {
			args := strings.Fields(line)
			cmdRoot.SetArgs(args)
			if err := cmdRoot.Execute(); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		}
	}
}
