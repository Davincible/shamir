package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/slip039"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
)

// NewCombineCommand creates the combine command using SLIP-0039
func NewCombineCommand() *cobra.Command {
	var (
		inputFile    string
		passphrase   string
		outputHex    bool
		outputText   bool
		showDetails  bool
	)

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combine SLIP-0039 shares to recover secret",
		SilenceUsage: true,
		Long: `Combine SLIP-0039 mnemonic shares to recover the original master secret.

Expects SLIP-0039 mnemonic shares (20 or 33 words each).
Shows both the recovered entropy and reconstructed mnemonic/BIP-39 seed for comparison.

Examples:
  # Combine shares interactively  
  shamir combine

  # Combine from file
  shamir combine --input shares.json

  # Combine with passphrase
  shamir combine --passphrase "my passphrase"
  
  # Show only hex output
  shamir combine --hex`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read mnemonics
			var mnemonics []string
			
			if inputFile != "" {
				loaded, err := readSlip039FromFile(inputFile)
				if err != nil {
					return err
				}
				mnemonics = loaded
			} else {
				collected, err := collectSlip039Mnemonics()
				if err != nil {
					return err
				}
				mnemonics = collected
			}

			if len(mnemonics) == 0 {
				return fmt.Errorf("no mnemonics provided")
			}

			// Get passphrase if not provided
			if passphrase == "" && !cmd.Flags().Changed("passphrase") {
				pass, err := readPassphrase("Enter passphrase (press Enter if none): ")
				if err != nil {
					return err
				}
				passphrase = pass
			}

			// Combine shares
			masterSecret, err := slip039.RecoverMasterSecret(mnemonics, passphrase)
			if err != nil {
				return fmt.Errorf("failed to recover secret: %w", err)
			}

			// Check if we need to decrypt the recovered secret (entropy encryption)
			// We attempt to decrypt with the same passphrase - if it works, it was encrypted
			var entropy []byte
			var wasEncrypted bool
			
			if passphrase != "" {
				// Try to decrypt - if this succeeds, the entropy was encrypted before sharing
				decrypted, err := slip039.DecryptMasterSecret(masterSecret, passphrase, 0, 0, true)
				if err == nil {
					// Successfully decrypted - this was encrypted entropy
					entropy = decrypted
					wasEncrypted = true
					
					// Remove padding if present (16-byte entropy becomes 17 bytes when padded)
					if len(entropy) == 17 && entropy[16] == 0 {
						entropy = entropy[:16]
					}
				} else {
					// Decryption failed - treat as raw entropy
					entropy = masterSecret
					wasEncrypted = false
				}
			} else {
				// No passphrase provided - treat as raw entropy
				entropy = masterSecret
				wasEncrypted = false
			}

			// Display result
			green := color.New(color.FgGreen, color.Bold)
			cyan := color.New(color.FgCyan, color.Bold)
			
			fmt.Println()
			green.Println("✓ Successfully recovered master secret!")
			if wasEncrypted {
				green.Println("✓ Successfully decrypted entropy!")
			}
			fmt.Println()
			
			if outputHex {
				cyan.Println("Master Secret (hex):")
				fmt.Printf("%x\n", entropy)
			} else if outputText {
				cyan.Println("Master Secret (text):")
				fmt.Printf("%s\n", string(entropy))
			} else {
				// Show recovered entropy and derived information
				cyan.Println("=== RECOVERY RESULTS ===")
				fmt.Println()
				
				yellow := color.New(color.FgYellow)
				yellow.Println("🎲 Recovered Entropy (Original Random Data):")
				fmt.Printf("%x\n", entropy)
				fmt.Printf("Length: %d bytes (%d bits)\n", len(entropy), len(entropy)*8)
				if wasEncrypted {
					fmt.Println("🔓 Entropy was encrypted before sharing and has been decrypted")
				}
				fmt.Println()
				fmt.Println("💡 This is the original entropy that was shared using SLIP-0039")
				fmt.Println()
				
				// Try to reconstruct the original mnemonic and BIP-39 seed
				if showDetails || true { // Always show by default now
					reconstructedMnemonic, err := bip39.NewMnemonic(entropy)
					if err == nil {
						yellow.Println("🔤 Reconstructed Mnemonic:")
						fmt.Println(reconstructedMnemonic)
						fmt.Println()
						
						// Generate BIP-39 seed from reconstructed mnemonic
						bip39Seed := bip39.NewSeed(reconstructedMnemonic, "")
						
						yellow.Println("🔑 BIP-39 Master Seed (for HD Wallet):")
						fmt.Printf("%x\n", bip39Seed)
						fmt.Printf("Length: %d bytes (%d bits)\n", len(bip39Seed), len(bip39Seed)*8)
						fmt.Println()
						fmt.Println("💡 This matches the BIP-39 seed from 'shamir generate --show-seed'")
					} else {
						yellow.Println("ℹ️  Could not reconstruct mnemonic (entropy may not be from BIP-39)")
						fmt.Printf("   Error: %v\n", err)
					}
				}
			}

			// Clear sensitive data
			for i := range masterSecret {
				masterSecret[i] = 0
			}
			for i := range entropy {
				entropy[i] = 0
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "File containing shares")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Passphrase used during splitting")
	cmd.Flags().BoolVar(&outputHex, "hex", false, "Output only as hexadecimal")
	cmd.Flags().BoolVar(&outputText, "text", false, "Output only as text")
	cmd.Flags().BoolVar(&showDetails, "details", false, "Show detailed cryptographic breakdown")

	return cmd
}

// collectSlip039Mnemonics interactively collects SLIP-0039 mnemonics
func collectSlip039Mnemonics() ([]string, error) {
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	
	fmt.Println()
	yellow.Println("Enter SLIP-0039 mnemonic shares (one per line)")
	fmt.Println("Press Enter twice when done")
	fmt.Println()
	
	reader := bufio.NewReader(os.Stdin)
	var mnemonics []string
	shareNum := 1
	
	for {
		fmt.Printf("Share %d: ", shareNum)
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		
		line = strings.TrimSpace(line)
		if line == "" {
			if len(mnemonics) == 0 {
				continue // Don't break on first empty line
			}
			break
		}
		
		// Clean up common prefixes that might be pasted with shares
		line = cleanShareInput(line)
		
		// Skip if line became empty after cleaning
		if line == "" {
			continue
		}
		
		// Validate mnemonic
		if err := slip039.ValidateMnemonic(line); err != nil {
			red.Printf("  ✗ Invalid share: %v\n", err)
			continue
		}
		
		// Get share info to display
		info, err := slip039.GetShareInfo(line)
		if err == nil {
			green.Printf("  ✓ Valid share (Group %d, Member %d)\n", 
				info.GroupIndex, info.MemberIndex)
		} else {
			green.Println("  ✓ Valid share")
		}
		
		mnemonics = append(mnemonics, line)
		shareNum++
	}
	
	if len(mnemonics) == 0 {
		return nil, fmt.Errorf("no valid shares provided")
	}
	
	fmt.Printf("\nCollected %d shares\n", len(mnemonics))
	return mnemonics, nil
}

// cleanShareInput removes common prefixes from pasted share input
func cleanShareInput(input string) string {
	input = strings.TrimSpace(input)
	
	// Remove common prefixes like "Share 1:", "Share 2:", etc.
	// Match pattern: "Share" + space + number + ":" + space
	if strings.HasPrefix(strings.ToLower(input), "share ") {
		// Find the colon and remove everything up to and including it
		colonIndex := strings.Index(input, ":")
		if colonIndex != -1 && colonIndex < 20 { // Reasonable limit for "Share X:"
			input = strings.TrimSpace(input[colonIndex+1:])
		}
	}
	
	// Remove other common prefixes
	prefixes := []string{
		"Share:",
		"Mnemonic:",
		"Words:",
	}
	
	for _, prefix := range prefixes {
		if strings.HasPrefix(strings.ToLower(input), strings.ToLower(prefix)) {
			input = strings.TrimSpace(input[len(prefix):])
			break
		}
	}
	
	return input
}

// readSlip039FromFile reads SLIP-0039 shares from a file (JSON or plain text)
func readSlip039FromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read the entire file content
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to detect format by checking if it starts with '{' (JSON)
	trimmed := strings.TrimSpace(string(content))
	if strings.HasPrefix(trimmed, "{") {
		// JSON format
		return readFromJSON(content, filename)
	} else {
		// Plain text format (one share per line)
		return readFromPlainText(content, filename)
	}
}

// readFromJSON parses JSON format files
func readFromJSON(content []byte, filename string) ([]string, error) {
	var data struct {
		Standard string     `json:"standard"`
		Shares   [][]string `json:"shares"`
		// Also support flat list for simple shares
		FlatShares []string `json:"flat_shares"`
	}

	if err := json.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("failed to parse JSON file: %w", err)
	}

	// Collect all shares
	var mnemonics []string
	
	if len(data.FlatShares) > 0 {
		mnemonics = data.FlatShares
	} else {
		for _, group := range data.Shares {
			mnemonics = append(mnemonics, group...)
		}
	}

	if len(mnemonics) == 0 {
		return nil, fmt.Errorf("no shares found in JSON file")
	}

	green := color.New(color.FgGreen)
	green.Printf("Loaded %d shares from JSON file %s\n", len(mnemonics), filename)
	
	return mnemonics, nil
}

// readFromPlainText parses plain text format files (one share per line)
func readFromPlainText(content []byte, filename string) ([]string, error) {
	lines := strings.Split(string(content), "\n")
	var mnemonics []string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue // Skip empty lines
		}
		
		// Clean up common prefixes that might be in the file
		line = cleanShareInput(line)
		
		// Skip if line became empty after cleaning
		if line == "" {
			continue
		}
		
		// Basic validation - should be a mnemonic phrase
		words := strings.Fields(line)
		if len(words) < 10 { // SLIP-0039 shares are typically 20 or 33 words
			continue // Skip lines that are clearly not mnemonic shares
		}
		
		mnemonics = append(mnemonics, line)
	}

	if len(mnemonics) == 0 {
		return nil, fmt.Errorf("no valid shares found in text file")
	}

	green := color.New(color.FgGreen)
	green.Printf("Loaded %d shares from text file %s\n", len(mnemonics), filename)
	
	return mnemonics, nil
}