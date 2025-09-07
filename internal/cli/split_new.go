package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Davincible/shamir/pkg/crypto/slip039"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// NewSplitCommandV2 creates the new default split command using SLIP-0039
func NewSplitCommandV2() *cobra.Command {
	var (
		threshold       int
		shares          int
		groupThreshold  int
		groupsSpec      string
		passphrase      string
		secretHex       string
		secretLength    int
		outputFile      string
		useLegacy       bool // Flag to use old implementation
	)

	cmd := &cobra.Command{
		Use:   "split",
		Short: "Split a secret into SLIP-0039 mnemonic shares",
		Long: `Split a master secret into SLIP-0039 mnemonic shares using
hierarchical Shamir's Secret Sharing with encryption.

By default, uses SLIP-0039 standard which is compatible with
Trezor and other hardware wallets.

Examples:
  # Simple 2-of-3 sharing (SLIP-0039)
  shamir split --threshold 2 --shares 3

  # Generate random 256-bit secret and split
  shamir split --threshold 3 --shares 5 --length 32

  # Advanced: Multiple groups
  shamir split --group-threshold 2 --groups "2/3,3/5"

  # Use legacy basic Shamir (non-standard)
  shamir split --legacy --threshold 2 --shares 3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if using legacy implementation
			if useLegacy {
				// Delegate to old implementation
				return runLegacySplit(threshold, shares, secretHex, outputFile)
			}

			// Use SLIP-0039 by default
			var groups []slip039.GroupConfiguration
			var actualGroupThreshold byte

			// Parse configuration
			if groupsSpec != "" {
				// Advanced mode with multiple groups
				parsedGroups, err := parseGroupsSpec(groupsSpec)
				if err != nil {
					return fmt.Errorf("invalid groups specification: %w", err)
				}
				groups = parsedGroups
				
				if groupThreshold <= 0 || groupThreshold > len(groups) {
					groupThreshold = len(groups) // Default to all groups
				}
				actualGroupThreshold = byte(groupThreshold)
			} else {
				// Simple mode
				if threshold <= 0 || shares <= 0 {
					return fmt.Errorf("--threshold and --shares are required")
				}
				groups = slip039.SimpleConfiguration(byte(threshold), byte(shares))
				actualGroupThreshold = 1
			}

			// Get or generate master secret
			var masterSecret []byte
			if secretHex != "" {
				decoded, err := hex.DecodeString(secretHex)
				if err != nil {
					return fmt.Errorf("invalid hex secret: %w", err)
				}
				masterSecret = decoded
			} else if secretLength > 0 {
				if secretLength != 16 && secretLength != 32 {
					return fmt.Errorf("secret length must be 16 or 32 bytes")
				}
				generated, err := slip039.GenerateMasterSecret(secretLength)
				if err != nil {
					return fmt.Errorf("failed to generate secret: %w", err)
				}
				masterSecret = generated
				
				yellow := color.New(color.FgYellow, color.Bold)
				yellow.Printf("Generated master secret: %x\n\n", masterSecret)
			} else {
				// Read secret interactively
				secret, err := readSecretInteractive()
				if err != nil {
					return err
				}
				masterSecret = secret
			}

			// Get passphrase if not provided
			if passphrase == "" && !cmd.Flags().Changed("passphrase") {
				pass, err := readPassphrase("Enter passphrase (optional, press Enter to skip): ")
				if err != nil {
					return err
				}
				passphrase = pass
			}

			// Split the secret using SLIP-0039
			mnemonics, err := slip039.SplitMasterSecret(
				masterSecret,
				passphrase,
				actualGroupThreshold,
				groups,
			)
			if err != nil {
				return fmt.Errorf("failed to split secret: %w", err)
			}

			// Save to file if requested
			if outputFile != "" {
				return saveSlip039ToFile(mnemonics, actualGroupThreshold, groups, outputFile)
			}

			// Display results
			displaySlip039Shares(mnemonics, actualGroupThreshold, groups)

			// Clear sensitive data
			for i := range masterSecret {
				masterSecret[i] = 0
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&threshold, "threshold", "t", 0, "Member threshold for simple mode")
	cmd.Flags().IntVarP(&shares, "shares", "n", 0, "Number of shares for simple mode")
	cmd.Flags().IntVar(&groupThreshold, "group-threshold", 0, "Number of groups required (advanced mode)")
	cmd.Flags().StringVar(&groupsSpec, "groups", "", "Groups specification (e.g., '2/3,3/5')")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Passphrase for encryption")
	cmd.Flags().StringVar(&secretHex, "secret", "", "Master secret in hex")
	cmd.Flags().IntVarP(&secretLength, "length", "l", 0, "Generate random secret of specified bytes (16 or 32)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output shares to file")
	cmd.Flags().BoolVar(&useLegacy, "legacy", false, "Use legacy basic Shamir implementation (non-standard)")

	return cmd
}

// runLegacySplit runs the old basic Shamir implementation
func runLegacySplit(threshold, shares int, secretHex, outputFile string) error {
	// This would call the old implementation
	// For now, just return an informative message
	yellow := color.New(color.FgYellow, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	
	red.Println("⚠️  WARNING: Legacy mode uses non-standard Shamir implementation")
	yellow.Println("This is NOT compatible with hardware wallets or SLIP-0039.")
	yellow.Println("Consider using the default SLIP-0039 implementation instead.")
	fmt.Println()
	
	// The actual legacy implementation would go here
	// For now, we'll just inform the user
	return fmt.Errorf("legacy implementation requires migration - use 'shamir legacy-split' command")
}

func saveSlip039ToFile(mnemonics [][]string, groupThreshold byte, groups []slip039.GroupConfiguration, filename string) error {
	type ShareFile struct {
		Standard       string                       `json:"standard"`
		GroupThreshold int                          `json:"group_threshold"`
		Groups         []slip039.GroupConfiguration `json:"groups"`
		Shares         [][]string                   `json:"shares"`
	}

	data := ShareFile{
		Standard:       "SLIP-0039",
		GroupThreshold: int(groupThreshold),
		Groups:         groups,
		Shares:         mnemonics,
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	green := color.New(color.FgGreen, color.Bold)
	green.Printf("✓ Shares saved to %s\n", filename)
	
	return nil
}