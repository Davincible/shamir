package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/crypto/slip039"
)

// NewSplitCommand creates the split command using SLIP-0039
func NewSplitCommand() *cobra.Command {
	var (
		threshold      int
		shares         int
		groupThreshold int
		groupsSpec     string
		passphrase     string
		secretHex      string
		secretLength   int
		outputFile     string
		noFiles        bool
	)

	cmd := &cobra.Command{
		Use:   "split",
		Short: "Split a secret into SLIP-0039 mnemonic shares",
		Long: `Split a master secret into SLIP-0039 mnemonic shares using
hierarchical Shamir's Secret Sharing with encryption.

Compatible with Trezor and other hardware wallets supporting SLIP-0039.

DEFAULT: Creates 3-of-5 shares with a new random secret if no options provided.

SECURITY: Shares are displayed on screen by default. Use --output only for
immediate printing, then delete the file with secure deletion tools.

Examples:
  # Use defaults (3-of-5 with random secret)
  shamir split

  # Simple 2-of-3 sharing
  shamir split --threshold 2 --shares 3

  # Generate random 256-bit secret and split
  shamir split --threshold 3 --shares 5 --length 32

  # Advanced: Multiple groups
  shamir split --group-threshold 2 --groups "2/3,3/5"
  
  # With passphrase protection
  shamir split --passphrase "mysecret"`,
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
				// Simple mode with defaults
				if threshold <= 0 && shares <= 0 {
					// Default to 3-of-5 if nothing specified
					threshold = 3
					shares = 5
					fmt.Println("Using default configuration: 3-of-5 shares")
					fmt.Println("(Use --threshold and --shares to customize)")
					fmt.Println()
				} else if threshold <= 0 || shares <= 0 {
					return fmt.Errorf("both --threshold and --shares must be specified together")
				}

				if threshold > shares {
					return fmt.Errorf("threshold cannot be greater than number of shares")
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
				// Interactive mode - ask what to do
				for {
					fmt.Println("Choose secret source:")
					fmt.Println("1. Generate new random secret (recommended)")
					fmt.Println("2. Enter BIP-39 mnemonic phrase")
					fmt.Println("3. Enter raw secret (hex or text)")
					fmt.Print("\nChoice [1]: ")

					var choice string
					fmt.Scanln(&choice)

					if choice == "" || choice == "1" {
						// Generate random 256-bit secret by default
						generated, err := slip039.GenerateMasterSecret(32)
						if err != nil {
							return fmt.Errorf("failed to generate secret: %w", err)
						}
						masterSecret = generated
						green := color.New(color.FgGreen, color.Bold)
						green.Println("✓ Generated 256-bit random secret")
						fmt.Println()
						break
					} else if choice == "2" {
						// BIP-39 mnemonic input (with smart stars)
						for {
							mnemonicInput, err := readMnemonicWithSmartStars("Enter BIP-39 mnemonic: ")
							if err != nil {
								return err
							}

							// Convert BIP-39 mnemonic to seed (first 32 bytes)
							m, err := mnemonic.FromWords(mnemonicInput)
							if err != nil {
								red := color.New(color.FgRed, color.Bold)
								red.Println("\n❌ Invalid BIP-39 mnemonic phrase")
								fmt.Println("\nPlease check that:")
								fmt.Println("• You entered all words correctly (typically 12, 18, or 24 words)")
								fmt.Println("• Words are separated by single spaces")
								fmt.Println("• All words are from the BIP-39 word list")
								fmt.Println("\nTry again or press Ctrl+C to exit.\n")
								continue // Try mnemonic input again
							}
							seed := m.Seed()
							masterSecret = seed[:32] // Use first 32 bytes (256-bit)

							fmt.Println("\n✓ Using 256-bit seed derived from BIP-39 mnemonic")
							break
						}
						break
					} else {
						// Raw secret input
						secret, err := readSecretInteractive()
						if err != nil {
							return err
						}

						// Ensure reasonable length for SLIP-0039
						if len(secret) > 32 {
							yellow := color.New(color.FgYellow)
							yellow.Printf("⚠️  Secret is %d bytes, truncating to 32 bytes for SLIP-0039\n", len(secret))
							secret = secret[:32]
						}

						masterSecret = secret
						break
					}
				}
			}

			// Get passphrase if not provided
			if passphrase == "" && !cmd.Flags().Changed("passphrase") {
				fmt.Println()
				cyan := color.New(color.FgCyan, color.Bold)
				cyan.Println("🔐 PASSPHRASE PROTECTION (Optional)")
				fmt.Println()
				fmt.Println("A passphrase adds an extra layer of security to your shares:")
				fmt.Println("• Even with enough shares, the passphrase is required to recover your secret")
				fmt.Println("• Uses PBKDF2 encryption (20,000+ iterations) for strong protection")
				fmt.Println("• Store your passphrase separately from your shares")
				fmt.Println("• Without the passphrase, your shares cannot be recovered")
				fmt.Println()
				yellow := color.New(color.FgYellow)
				yellow.Println("⚠️  WARNING: If you forget your passphrase, your secret is permanently lost!")
				fmt.Println()

				pass, err := readPassphraseWithStars("Enter passphrase (press Enter to skip): ")
				if err != nil {
					return err
				}

				if pass != "" {
					green := color.New(color.FgGreen)
					green.Println("\n✓ Passphrase protection enabled")
				} else {
					fmt.Println("\n⚠️  No passphrase - shares alone can recover your secret")
				}
				fmt.Println()

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
