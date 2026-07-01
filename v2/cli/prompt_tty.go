package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func stdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func requireInteractiveTTY() {
	if !stdinIsTTY() {
		fmt.Println("Error: --interactive requires a terminal")
		os.Exit(1)
	}
}

func requireTTYOrYes(yes bool, action string) {
	if yes || stdinIsTTY() {
		return
	}
	fmt.Printf("Error: %s requires a terminal or -y\n", action)
	os.Exit(1)
}
