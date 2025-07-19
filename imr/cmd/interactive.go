package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/c-bata/go-prompt"
	"github.com/spf13/cobra"
)

// Reference to the root command, set by the root package
var cmdRoot *cobra.Command

// SetRootCommand allows the root package to provide the root command reference
func SetRootCommand(cmd *cobra.Command) {
	cmdRoot = cmd
}

// Track current input and guide state
type promptState struct {
	input string
	guide string
}

var state promptState

// updateGuide updates the current guide based on input
func updateGuide(input string) string {
	// fmt.Printf("[updateGuide: arg: '%s']\n", input)
	words := strings.Fields(input)
	if len(words) == 0 {
		return ""
	}

	cmd, _, err := cmdRoot.Find(words[:1])
	if err != nil {
		return ""
	}

	argPos := len(words) - 1
	if strings.HasSuffix(input, " ") {
		argPos++
	}

	// Get guide from annotations
	if cmd.Annotations != nil {
		if guide, ok := cmd.Annotations[fmt.Sprintf("arg%d_guide", argPos)]; ok {
			// fmt.Printf("[updateGuide: returning '%s']", guide)
			return guide
		}
	}

	// Fallback to Use field parsing if no annotation
	args := strings.Fields(cmd.Use)[1:]
	if argPos < len(args) {
		tmp := fmt.Sprintf("(%s)", strings.Trim(args[argPos], "[]<>"))
		// fmt.Printf("[updateGuide: returning '%s']\n", tmp)
		return tmp
	}
	return ""
}

func startInteractiveMode() {
	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("tdns-imr> "),
		prompt.OptionTitle("TDNS-IMR Interactive Shell"),
		// prompt.OptionInputTextColor(prompt.Black),
		prompt.OptionMaxSuggestion(5),
	)
	p.Run()
	exec.Command("stty", "sane").Run()
	os.Exit(0)
}

// executor handles command execution
func executor(input string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return
	}
	if input == "exit" || input == "quit" {
		fmt.Println("Goodbye!")
		return // XXX: not enough to terminate
		// exec.Command("stty", "sane").Run()
		// os.Exit(0)
	}

	// Split the input into args and execute via Cobra
	args := strings.Fields(input)

	// Find the command but don't execute it via rootCmd.Execute()
	cmd, flags, err := cmdRoot.Find(args)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Execute just the command's Run function with remaining args
	if cmd.Run != nil {
		cmd.Run(cmd, flags)
	} else if cmd.RunE != nil {
		if err := cmd.RunE(cmd, flags); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
}

// findCommonPrefix returns the common prefix of all matches
func findCommonPrefix(matches []string) string {
	if len(matches) == 0 {
		return ""
	}
	if len(matches) == 1 {
		return matches[0]
	}

	prefix := matches[0]
	for _, match := range matches[1:] {
		for i := range prefix {
			if i >= len(match) || match[i] != prefix[i] {
				prefix = prefix[:i]
				break
			}
		}
	}
	return prefix
}

// completer provides completion suggestions
func completer(d prompt.Document) []prompt.Suggest {
	// fmt.Printf("[comp: arg: '%+v']", d)

	input := d.TextBeforeCursor()
	words := strings.Fields(input)
	word := d.GetWordBeforeCursor()

	// fmt.Printf("\nDEBUG: TAB pressed")
	// fmt.Printf("\n  input: '%s'", input)
	// fmt.Printf("\n  word: '%s'", word)
	// fmt.Printf("\n  words: %v", words)
	// fmt.Printf("\n  line: '%s'", d.Text)
	// fmt.Printf("\n")

	// If we have a complete command and hit tab again, show the guide
	if len(words) > 0 && strings.HasSuffix(input, " ") {
		// fmt.Printf("[comp: calling updateGuide]")
		guide := updateGuide(input)
		if guide != "" {
			// fmt.Printf("[comp: there is a guide: '%s']", guide)
			// Keep the existing input and show guide
			return []prompt.Suggest{{Text: input, Description: guide}}
		}
	}

	// If we're at the start of the line or completing first word
	if len(words) == 0 || (len(words) == 1 && !strings.HasSuffix(input, " ")) {
		// Find all matching commands
		matches := []string{}
		for _, cmd := range cmdRoot.Commands() {
			if strings.HasPrefix(cmd.Name(), word) {
				matches = append(matches, cmd.Name())
			}
		}

		// If no matches, return empty
		if len(matches) == 0 {
			return []prompt.Suggest{}
		}

		// If one match, return it with a space and guide
		if len(matches) == 1 {
			return []prompt.Suggest{{
				Text:        matches[0] + " ",
				Description: updateGuide(matches[0] + " "),
			}}
		}

		// Multiple matches: find common prefix and show all possibilities
		prefix := findCommonPrefix(matches)
		if len(prefix) > len(word) {
			// We can complete partially
			return []prompt.Suggest{{Text: prefix, Description: ""}}
		}

		// Show all possibilities
		suggestions := []prompt.Suggest{}
		for _, match := range matches {
			cmd, _, _ := cmdRoot.Find([]string{match})
			suggestions = append(suggestions, prompt.Suggest{
				Text:        match,
				Description: cmd.Short,
			})
		}
		return suggestions
	}

	return []prompt.Suggest{}
}

// changeLivePrefix updates the prompt prefix including the guide
func changeLivePrefix() (string, bool) {
	if state.guide != "" {
		return fmt.Sprintf("tdns> %s%s", state.input, state.guide), true
	}
	return "tdns> ", false
}

// Track current input for live prefix
var currentInput string

// getCommandSuggestions returns available commands from Cobra
func getCommandSuggestions() []prompt.Suggest {
	suggestions := []prompt.Suggest{}

	for _, cmd := range cmdRoot.Commands() {
		suggestions = append(suggestions, prompt.Suggest{
			Text:        cmd.Name(),
			Description: cmd.Short,
		})
	}

	// Add exit commands
	suggestions = append(suggestions, prompt.Suggest{
		Text:        "exit",
		Description: "Exit the interactive shell",
	})
	suggestions = append(suggestions, prompt.Suggest{
		Text:        "quit",
		Description: "Exit the interactive shell",
	})

	return suggestions
}
