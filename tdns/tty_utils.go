/*
 * Copyright (c) DNS TAPIR
 */
package tdns

import (
	"bufio"
	"strconv"

	"fmt"
	"os"
	"strings"
)

func Chomp(s string) string {
        if len(s) > 0 && strings.HasSuffix(s, "\n") {
                return s[:len(s)-1]
        }
        return s
}

func TtyQuestion(query, oldval string, force bool) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [%s]: ", query, oldval)
		text, _ := reader.ReadString('\n')
		if text == "\n" {
			fmt.Printf("[empty response, keeping previous value]\n")
			if oldval != "" {
				return oldval // all ok
			} else if force {
				fmt.Printf("[error: previous value was empty string, not allowed]\n")
				continue
			}
			return oldval
		} else {
			// regardless of force we accept non-empty response
			return strings.TrimSuffix(text, "\n")
		}
	}
}

func TtyIntQuestion(query string, oldval int, force bool) int {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [%d]: ", query, oldval)
		text, _ := reader.ReadString('\n')
		if text == "\n" {
			fmt.Printf("[empty response, keeping previous value]\n")
			if oldval != 0 {
				return oldval // all ok
			} else if force {
				fmt.Printf("[error: previous value was empty string, not allowed]\n")
				continue
			}
			return oldval
		} else {
			text = Chomp(text)
			// regardless of force we accept non-empty response
			val, err := strconv.Atoi(text)
			if err != nil {
				fmt.Printf("Error: %s is not an integer\n", text)
				continue
			}
			return val
		}
	}
}

func TtyYesNo(query, defval string) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [%s]: ", query, defval)
		text, _ := reader.ReadString('\n')
		if text == "\n" {
			if defval != "" {
				fmt.Printf("[empty response, using default value]\n")
				return defval // all ok
			}
			fmt.Printf("[error: default value is empty string, not allowed]\n")
			continue
		} else {
			val := strings.ToLower(strings.TrimSuffix(text, "\n"))
			if (val == "yes") || (val == "no") {
				return val
			}
			fmt.Printf("Answer '%s' not accepted. Only yes or no.\n", val)
		}
	}
}

func TtyRadioButtonQ(query, defval string, choices []string) string {
	var C []string
	for _, c := range choices {
		C = append(C, strings.ToLower(c))
	}

	allowed := func(str string) bool {
		for _, c := range C {
			if str == c {
				return true
			}
		}
		return false
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [%s]: ", query, defval)
		text, _ := reader.ReadString('\n')
		if text == "\n" {
			if defval != "" {
				fmt.Printf("[empty response, using default value]\n")
				return defval // all ok
			}
			fmt.Printf("[error: default value is empty string, not allowed]\n")
			continue
		} else {
			val := strings.ToLower(strings.TrimSuffix(text, "\n"))
			if allowed(val) {
				return val
			}
			fmt.Printf("Answer '%s' not accepted. Possible choices are: %v\n", val, choices)
		}
	}
}
