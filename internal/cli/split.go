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

// NewSplitCommand creates the split command using SLIP-0039
func NewSplitCommand() *cobra.Command {
	var (
		threshold       int
		shares          int
		groupThreshold  int
		groupsSpec      string
		passphrase      string
		secretHex       string
		secretLength    int
		outputFile      string
		noFiles         bool
	)

	cmd := &cobra.Command{
		Use:   "split",
		Short: "Split a secret into SLIP-0039 mnemonic shares",
		Long: `Split a master secret into SLIP-0039 mnemonic shares using
hierarchical Shamir's Secret Sharing with encryption.

Compatible with Trezor and other hardware wallets supporting SLIP-0039.

Examples:
  # Simple 2-of-3 sharing
  shamir split --threshold 2 --shares 3

  # Generate random 256-bit secret and split
  shamir split --threshold 3 --shares 5 --length 32

  # Advanced: Multiple groups
  shamir split --group-threshold 2 --groups "2/3,3/5"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use SLIP-0039
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

			// Display results (always show unless --no-display is used)
			if !noFiles || outputFile == "" {
				displaySlip039Shares(mnemonics, actualGroupThreshold, groups)
			}
			
			// Save to file if explicitly requested
			if outputFile != "" && !noFiles {
				fmt.Println()
				red := color.New(color.FgRed, color.Bold)
				red.Println("⚠️  SECURITY WARNING: Saving shares to file!")
				fmt.Println("• Delete this file immediately after use")
				fmt.Println("• Never store on cloud-synced drives")
				fmt.Println("• Use secure deletion (shred -vfz -n 3)")
				fmt.Println()
				
				return saveSlip039ToFile(mnemonics, actualGroupThreshold, groups, outputFile)
			} else if outputFile != "" && noFiles {
				return fmt.Errorf("cannot use --output with --no-files")
			}

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
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output shares to file (SECURITY RISK - use only for immediate printing)")
	cmd.Flags().BoolVar(&noFiles, "no-files", false, "Never save to files (display only)")

	return cmd
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