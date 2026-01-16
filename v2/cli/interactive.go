package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/c-bata/go-prompt"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Reference to the root command, set by the root package
var cmdRoot *cobra.Command

// SetRootCommand allows the root package to provide the root command reference
func SetRootCommand(cmd *cobra.Command) {
	cmdRoot = cmd
}

// Global channel to signal termination
// var exitCh chan struct{}

// exitCmd represents the exit command
var ExitCmd = &cobra.Command{
	Use:   "exit",
	Short: "Exit the interactive shell",
	Run: func(cmd *cobra.Command, args []string) {
		Terminate()
	},
}

// quitCmd represents the quit command
var QuitCmd = &cobra.Command{
	Use:    "quit",
	Short:  "Exit the interactive shell",
	Long:   `Exit the interactive shell`,
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		Terminate()
	},
}

func Terminate() {
	fmt.Println("Goodbye!")
	// Clean up terminal and exit immediately
	restoreTTY()
	os.Exit(0)
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

// original TTY state captured at interactive start
var (
	origTTYState *term.State
	origTTYFD    int
	ttyFile      *os.File
)

func restoreTTY() {
	if origTTYState != nil {
		_ = term.Restore(origTTYFD, origTTYState)
		// Some environments need explicit re-enabling of isig/canon/echo
		_ = exec.Command("stty", "isig", "icanon", "echo").Run()
	} else {
		// Fallback if we never captured state
		_ = exec.Command("stty", "sane").Run()
	}
	if ttyFile != nil {
		_ = ttyFile.Close()
		ttyFile = nil
	}
}

func StartInteractiveMode() {
	// Capture current TTY state (prefer /dev/tty over stdin) and arrange restoration on exit/signals
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		ttyFile = f
		origTTYFD = int(f.Fd())
	} else {
		origTTYFD = int(os.Stdin.Fd())
	}
	if term.IsTerminal(origTTYFD) {
		if st, err := term.GetState(origTTYFD); err == nil {
			origTTYState = st
		}
	}
	sigch := make(chan os.Signal, 2)
	signal.Notify(sigch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		<-sigch
		restoreTTY()
		os.Exit(0)
	}()

	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("tdns-imr> "),
		prompt.OptionTitle("TDNS-IMR Interactive Shell"),
		// prompt.OptionInputTextColor(prompt.Black),
		prompt.OptionMaxSuggestion(5),
	)

	p.Run()
	restoreTTY()
	os.Exit(0)
}

// executor handles command execution
func executor(input string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return
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
	// Friendly behavior: if user typed "query" with no args (often from "q<TAB><ENTER>"),
	// assume they meant to quit.
	if cmd.Name() == "query" && (len(flags) == 0 || (len(flags) == 1 && strings.TrimSpace(flags[0]) == "")) {
		fmt.Println("query was empty, assuming you meant 'quit'")
		Terminate()
		return
	}
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
	// Get the full text and current word being completed
	fullText := d.Text
	currentWord := d.GetWordBeforeCursor()

	// Split the full text into words
	words := strings.Fields(fullText)

	// Determine what we're completing
	var word string
	if len(words) > 0 {
		// If we have words, use the current word being typed
		word = currentWord
	} else {
		// If no words, we're at the start of the line
		word = ""
	}

	// If we have a complete command and hit tab again, show subcommands first, then guide
	if len(words) > 0 && currentWord == "" && strings.HasSuffix(fullText, " ") {
		// First try to show subcommand suggestions
		subSuggestions := getSubcommandSuggestions(words, "")
		if len(subSuggestions) > 0 {
			return subSuggestions
		}

		// If no subcommands, show the guide
		guide := updateGuide(fullText)
		if guide != "" {
			// Keep the existing input and show guide
			return []prompt.Suggest{{Text: fullText, Description: guide}}
		}
	}

	// Handle top-level command completion (when we're at the start or completing the first word)
	if len(words) == 0 || (len(words) == 1 && !strings.HasSuffix(fullText, " ")) {
		return getTopLevelCommands(word)
	}

	// Handle subcommand completion (when we have a complete command and are adding more)
	if len(words) >= 1 {
		return getSubcommandSuggestions(words, word)
	}

	return []prompt.Suggest{}
}

// getTopLevelCommands returns suggestions for top-level commands
func getTopLevelCommands(word string) []prompt.Suggest {
	matches := []string{}

	if word == "" {
		// When word is empty, show all commands except completion
		for _, cmd := range cmdRoot.Commands() {
			if cmd.Name() != "completion" && !cmd.Hidden {
				matches = append(matches, cmd.Name())
			}
		}
	} else {
		// When word has a value, filter commands that start with it
		for _, cmd := range cmdRoot.Commands() {
			if cmd.Name() != "completion" && !cmd.Hidden && strings.HasPrefix(cmd.Name(), word) {
				matches = append(matches, cmd.Name())
			}
		}
	}

	if len(matches) == 0 {
		return []prompt.Suggest{}
	}

	if len(matches) == 1 {
		// Check if this command has subcommands
		cmd, _, _ := cmdRoot.Find([]string{matches[0]})
		if len(cmd.Commands()) > 0 {
			// If the command has subcommands, return them with the parent command prefix
			subSuggestions := []prompt.Suggest{}
			for _, subcmd := range cmd.Commands() {
				subSuggestions = append(subSuggestions, prompt.Suggest{
					Text:        matches[0] + " " + subcmd.Name(),
					Description: subcmd.Short,
				})
			}
			if len(subSuggestions) > 0 {
				return subSuggestions
			}
		}

		// If no subcommands, return the command with a space
		return []prompt.Suggest{{
			Text:        matches[0] + " ",
			Description: updateGuide(matches[0] + " "),
		}}
	}

	// Multiple matches: show all possibilities
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

// getSubcommandSuggestions returns suggestions for subcommands
func getSubcommandSuggestions(words []string, word string) []prompt.Suggest {
	// Find the parent command
	var parentCmd *cobra.Command
	var err error

	if word == "" {
		// When word is empty, we want to show all subcommands of the current command
		parentCmd, _, err = cmdRoot.Find(words)
	} else {
		// Find the parent command (all words except the last one)
		parentWords := words[:len(words)-1]
		parentCmd, _, err = cmdRoot.Find(parentWords)
	}

	if err != nil {
		return []prompt.Suggest{}
	}

	// Get subcommands of the parent command
	matches := []string{}
	for _, subcmd := range parentCmd.Commands() {
		if strings.HasPrefix(subcmd.Name(), word) {
			matches = append(matches, subcmd.Name())
		}
	}

	if len(matches) == 0 {
		return []prompt.Suggest{}
	}

	if len(matches) == 1 {
		// Return just the subcommand name with a space
		return []prompt.Suggest{{
			Text:        matches[0] + " ",
			Description: updateGuide(strings.Join(words, " ") + " " + matches[0] + " "),
		}}
	}

	// Multiple matches: find common prefix
	prefix := findCommonPrefix(matches)
	if len(prefix) > len(word) {
		// We can complete partially - return just the prefix
		return []prompt.Suggest{{Text: prefix, Description: ""}}
	}

	// Show all possibilities - return just the subcommand names
	suggestions := []prompt.Suggest{}
	for _, match := range matches {
		subcmd, _, _ := parentCmd.Find([]string{match})
		suggestions = append(suggestions, prompt.Suggest{
			Text:        match,
			Description: subcmd.Short,
		})
	}
	return suggestions
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
