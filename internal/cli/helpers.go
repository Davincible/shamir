package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/Davincible/shamir/pkg/crypto/slip039"
	"github.com/fatih/color"
	"golang.org/x/term"
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

// readSecretInteractive reads a secret from the terminal
func readSecretInteractive() ([]byte, error) {
	fmt.Print("Enter your secret: ")

	if term.IsTerminal(int(syscall.Stdin)) {
		secret, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		
		if len(secret) == 0 {
			return nil, fmt.Errorf("secret cannot be empty")
		}
		
		// Ensure even length for SLIP-0039
		if len(secret)%2 != 0 {
			// Pad with a space to make it even
			secret = append(secret, ' ')
		}
		
		return secret, nil
	}
	
	// Fallback for non-terminal
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	
	secret := []byte(strings.TrimSpace(input))
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret cannot be empty")
	}
	
	// Ensure even length
	if len(secret)%2 != 0 {
		secret = append(secret, ' ')
	}
	
	return secret, nil
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
			fmt.Printf("\nShare %d-%d:\n", i+1, j+1)
			
			// Display share with word numbers
			words := strings.Fields(share)
			for k := 0; k < len(words); k += 4 {
				end := k + 4
				if end > len(words) {
					end = len(words)
				}
				fmt.Printf("  %s\n", strings.Join(words[k:end], " "))
			}
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