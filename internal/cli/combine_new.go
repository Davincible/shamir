package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/slip039"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// NewCombineCommandV2 creates the new default combine command using SLIP-0039
func NewCombineCommandV2() *cobra.Command {
	var (
		inputFile   string
		passphrase  string
		outputHex   bool
		outputText  bool
		useLegacy   bool
	)

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combine SLIP-0039 shares to recover secret",
		Long: `Combine SLIP-0039 mnemonic shares to recover the original master secret.

By default, expects SLIP-0039 mnemonic shares (20 or 33 words each).
Use --legacy flag for old hex/base64 shares.

Examples:
  # Combine SLIP-0039 shares interactively
  shamir combine

  # Combine from file
  shamir combine --input shares.json

  # Combine with passphrase
  shamir combine --passphrase "my passphrase"

  # Use legacy mode for old shares
  shamir combine --legacy`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if using legacy implementation
			if useLegacy {
				return runLegacyCombine(inputFile)
			}

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

			// Display result
			green := color.New(color.FgGreen, color.Bold)
			cyan := color.New(color.FgCyan, color.Bold)
			
			fmt.Println()
			green.Println("✓ Successfully recovered master secret!")
			fmt.Println()
			
			if outputHex {
				cyan.Println("Master Secret (hex):")
				fmt.Printf("%x\n", masterSecret)
			} else if outputText {
				cyan.Println("Master Secret (text):")
				fmt.Printf("%s\n", string(masterSecret))
			} else {
				// Show both by default
				cyan.Println("Master Secret:")
				fmt.Printf("  Text: %s\n", string(masterSecret))
				fmt.Printf("  Hex:  %x\n", masterSecret)
			}

			// Clear sensitive data
			for i := range masterSecret {
				masterSecret[i] = 0
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "File containing shares")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Passphrase used during splitting")
	cmd.Flags().BoolVar(&outputHex, "hex", false, "Output only as hexadecimal")
	cmd.Flags().BoolVar(&outputText, "text", false, "Output only as text")
	cmd.Flags().BoolVar(&useLegacy, "legacy", false, "Use legacy basic Shamir implementation")

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

// readSlip039FromFile reads SLIP-0039 shares from a JSON file
func readSlip039FromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data struct {
		Standard string     `json:"standard"`
		Shares   [][]string `json:"shares"`
		// Also support flat list for simple shares
		FlatShares []string `json:"flat_shares"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
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
		return nil, fmt.Errorf("no shares found in file")
	}

	green := color.New(color.FgGreen)
	green.Printf("Loaded %d shares from %s\n", len(mnemonics), filename)
	
	return mnemonics, nil
}

// runLegacyCombine runs the old basic Shamir implementation
func runLegacyCombine(inputFile string) error {
	yellow := color.New(color.FgYellow, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	
	red.Println("⚠️  WARNING: Legacy mode uses non-standard Shamir implementation")
	yellow.Println("This is for recovering old shares only.")
	yellow.Println("New shares should use SLIP-0039 (default).")
	fmt.Println()
	
	return fmt.Errorf("legacy implementation requires migration - use 'shamir legacy-combine' command")
}