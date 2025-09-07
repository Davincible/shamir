package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"golang.org/x/term"

	"github.com/Davincible/shamir/pkg/crypto/slip039"
)

// readPassphrase reads a passphrase from the terminal
func readPassphrase(prompt string) (string, error) {
	fmt.Print(prompt)

	if term.IsTerminal(int(syscall.Stdin)) {
		passBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(passBytes), nil
	}

	// Fallback for non-terminal
	reader := bufio.NewReader(os.Stdin)
	pass, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(pass), nil
}

// readPasswordWithStars reads a password and displays stars in real-time
func readPasswordWithStars(prompt string) (string, error) {
	fmt.Print(prompt)

	if !term.IsTerminal(int(syscall.Stdin)) {
		// Fallback for non-terminal
		reader := bufio.NewReader(os.Stdin)
		pass, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(pass), nil
	}

	// Save current terminal state
	oldState, err := term.MakeRaw(int(syscall.Stdin))
	if err != nil {
		// Fallback to hidden input if raw mode fails
		passBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		fmt.Print(strings.Repeat("*", min(len(passBytes), 24)))
		fmt.Println()
		return string(passBytes), nil
	}
	defer term.Restore(int(syscall.Stdin), oldState)

	var password []byte
	var b [1]byte
	var inWord bool

	for {
		_, err := os.Stdin.Read(b[:])
		if err != nil {
			return "", err
		}

		char := b[0]

		switch char {
		case '\n', '\r': // Enter
			fmt.Println()
			return string(password), nil

		case 127, 8: // Backspace/Delete
			if len(password) > 0 {
				password = password[:len(password)-1]
				fmt.Print("\b \b")

				// Update inWord state based on what's left
				if len(password) == 0 {
					inWord = false
				} else {
					// Check if we're still in a word
					inWord = password[len(password)-1] != ' '
				}
			}

		case 3: // Ctrl+C
			fmt.Println()
			return "", fmt.Errorf("interrupted")

		case 4: // Ctrl+D (EOF)
			if len(password) == 0 {
				fmt.Println()
				return "", fmt.Errorf("EOF")
			}

		default:
			// Only accept printable ASCII characters and spaces
			if char >= 32 && char <= 126 {
				password = append(password, char)

				if char == ' ' {
					fmt.Print(" ")
					inWord = false
				} else {
					// Non-space character
					if !inWord {
						// Starting a new word
						fmt.Print("*")
						inWord = true
					}
				}
			}
		}
	}
}

// readPassphraseWithStars reads a passphrase and displays one star per character
func readPassphraseWithStars(prompt string) (string, error) {
	fmt.Print(prompt)

	if !term.IsTerminal(int(syscall.Stdin)) {
		// Fallback for non-terminal
		reader := bufio.NewReader(os.Stdin)
		pass, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(pass), nil
	}

	// Save current terminal state
	oldState, err := term.MakeRaw(int(syscall.Stdin))
	if err != nil {
		// Fallback to hidden input if raw mode fails
		passBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		fmt.Print(strings.Repeat("*", len(passBytes)))
		fmt.Println()
		return string(passBytes), nil
	}
	defer term.Restore(int(syscall.Stdin), oldState)

	var password []byte
	var b [1]byte

	for {
		_, err := os.Stdin.Read(b[:])
		if err != nil {
			return "", err
		}

		char := b[0]

		switch char {
		case '\n', '\r': // Enter
			fmt.Println()
			return string(password), nil

		case 127, 8: // Backspace/Delete
			if len(password) > 0 {
				password = password[:len(password)-1]
				fmt.Print("\b \b")
			}

		case 3: // Ctrl+C
			fmt.Println()
			return "", fmt.Errorf("interrupted")

		case 4: // Ctrl+D (EOF)
			if len(password) == 0 {
				fmt.Println()
				return "", fmt.Errorf("EOF")
			}

		default:
			// Only accept printable ASCII characters and spaces
			if char >= 32 && char <= 126 {
				password = append(password, char)
				fmt.Print("*")
			}
		}
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// readSecretInteractive reads a secret from the terminal
func readSecretInteractive() ([]byte, error) {
	secret, err := readPasswordWithStars("Enter your secret: ")
	if err != nil {
		return nil, err
	}

	if len(secret) == 0 {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	secretBytes := []byte(secret)

	// Ensure even length for SLIP-0039
	if len(secretBytes)%2 != 0 {
		// Pad with a space to make it even
		secretBytes = append(secretBytes, ' ')
	}

	return secretBytes, nil
}

// parseGroupsSpec parses a groups specification string
func parseGroupsSpec(spec string) ([]slip039.GroupConfiguration, error) {
	parts := strings.Split(spec, ",")
	groups := make([]slip039.GroupConfiguration, len(parts))

	for i, part := range parts {
		part = strings.TrimSpace(part)
		thresholdAndCount := strings.Split(part, "/")

		if len(thresholdAndCount) != 2 {
			return nil, fmt.Errorf("invalid group spec '%s', expected format: threshold/count", part)
		}

		threshold, err := strconv.Atoi(thresholdAndCount[0])
		if err != nil || threshold <= 0 || threshold > 16 {
			return nil, fmt.Errorf("invalid threshold in '%s'", part)
		}

		count, err := strconv.Atoi(thresholdAndCount[1])
		if err != nil || count <= 0 || count > 16 {
			return nil, fmt.Errorf("invalid count in '%s'", part)
		}

		if threshold > count {
			return nil, fmt.Errorf("threshold cannot exceed count in '%s'", part)
		}

		groups[i] = slip039.GroupConfiguration{
			MemberThreshold: byte(threshold),
			MemberCount:     byte(count),
		}
	}

	return groups, nil
}

// displaySlip039Shares displays the generated shares
func displaySlip039Shares(mnemonics [][]string, groupThreshold byte, groups []slip039.GroupConfiguration) {
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	fmt.Println()
	yellow.Println("=== SLIP-0039 MNEMONIC SHARES ===")
	fmt.Println()

	if len(groups) == 1 {
		// Simple mode
		green.Printf("Created %d shares with threshold %d\n",
			groups[0].MemberCount, groups[0].MemberThreshold)
		fmt.Printf("Any %d shares can reconstruct the original secret\n\n",
			groups[0].MemberThreshold)
	} else {
		// Advanced mode
		green.Printf("Created %d groups with group threshold %d\n",
			len(groups), groupThreshold)
		fmt.Printf("Need shares from at least %d groups to reconstruct\n\n",
			groupThreshold)
	}

	for i, group := range mnemonics {
		if len(groups) > 1 {
			cyan.Printf("Group %d (threshold %d of %d):\n",
				i+1, groups[i].MemberThreshold, groups[i].MemberCount)
		}

		for j, share := range group {
			yellow.Printf("\nShare %d-%d:\n", i+1, j+1)

			// Check if share is unusually long
			words := strings.Fields(share)
			if len(words) > 35 {
				red.Printf("⚠️  WARNING: Share has %d words (expected 20-33 for SLIP-0039)\n", len(words))
				red.Println("This suggests your input secret was too large.")
				fmt.Println("Consider using option 2 to convert BIP-39 to proper seed.")
				fmt.Println()
			}

			// Display share cleanly - just the words
			green.Printf("  %s\n", share)
		}

		if len(groups) > 1 {
			fmt.Println()
		}
	}

	fmt.Println()
	red.Println("⚠️  SECURITY WARNING:")
	fmt.Println("- Each share should be stored in a different secure location")
	fmt.Println("- Never store shares together or electronically without encryption")
	fmt.Println("- Test recovery with minimum shares before relying on this backup")
	fmt.Println("- These shares are SLIP-0039 compatible (Trezor Model T, etc.)")
}
