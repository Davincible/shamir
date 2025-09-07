package cli

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/crypto/secretsharing"
	"github.com/Davincible/shamir/pkg/crypto/slip039"
)

// NewSplitCommand creates the split command using SLIP-0039
func NewSplitCommand() *cobra.Command {
	var (
		scheme         string
		threshold      int
		shares         int
		groupThreshold int
		groupsSpec     string
		passphrase     string
		secretHex      string
		secretLength   int
		outputFile     string
		noFiles        bool
		curveType      string
	)

	cmd := &cobra.Command{
		Use:   "split",
		Short: "Split a secret using various Secret Sharing Schemes",
		Long: `Split a master secret using different Secret Sharing Schemes:
- SLIP-0039: Hierarchical sharing with mnemonic encoding (default)
- PVSS: Publicly Verifiable Secret Sharing with elliptic curve cryptography

DEFAULT: Creates 3-of-5 SLIP-0039 shares with a new random secret.

SECURITY: Shares are displayed on screen by default. Use --output only for
immediate printing, then delete the file with secure deletion tools.

Examples:
  # Use defaults (3-of-5 SLIP-0039 with random secret)
  shamir split

  # SLIP-0039 with specific parameters
  shamir split --scheme slip039 --threshold 2 --shares 3

  # PVSS (Publicly Verifiable Secret Sharing)
  shamir split --scheme pvss --threshold 3 --shares 5

  # SLIP-0039 advanced: Multiple groups
  shamir split --scheme slip039 --group-threshold 2 --groups "2/3,3/5"
  
  # PVSS with P-256 curve
  shamir split --scheme pvss --threshold 2 --shares 3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Handle scheme selection
			var config secretsharing.SecretSharingConfig

			// Set scheme type
			switch scheme {
			case "slip039":
				config.Scheme = secretsharing.SchemeSLIP039
			case "pvss":
				config.Scheme = secretsharing.SchemePVSS
				config.CurveType = curveType
			default:
				return fmt.Errorf("unsupported scheme: %s (supported: slip039, pvss)", scheme)
			}

			// Parse group configuration
			if groupsSpec != "" {
				// Advanced mode with multiple groups (SLIP-0039 only)
				if scheme != "slip039" {
					return fmt.Errorf("advanced group configuration is only supported with SLIP-0039")
				}
				
				parsedGroups, err := parseGroupsSpec(groupsSpec)
				if err != nil {
					return fmt.Errorf("invalid groups specification: %w", err)
				}
				
				// Convert to unified format
				config.Groups = make([]secretsharing.GroupConfiguration, len(parsedGroups))
				for i, g := range parsedGroups {
					config.Groups[i] = secretsharing.GroupConfiguration{
						MemberThreshold: int(g.MemberThreshold),
						MemberCount:     int(g.MemberCount),
					}
				}

				if groupThreshold <= 0 || groupThreshold > len(config.Groups) {
					groupThreshold = len(config.Groups) // Default to all groups
				}
				config.GroupThreshold = groupThreshold
			} else {
				// Simple mode with defaults
				if threshold <= 0 && shares <= 0 {
					// Default to 3-of-5 if nothing specified
					threshold = 3
					shares = 5
					fmt.Printf("Using default configuration: 3-of-5 %s shares\n", scheme)
					fmt.Println("(Use --threshold and --shares to customize)")
					fmt.Println()
				} else if threshold <= 0 || shares <= 0 {
					return fmt.Errorf("both --threshold and --shares must be specified together")
				}

				if threshold > shares {
					return fmt.Errorf("threshold cannot be greater than number of shares")
				}

				// Single group configuration
				config.Groups = []secretsharing.GroupConfiguration{{
					MemberThreshold: threshold,
					MemberCount:     shares,
				}}
				config.GroupThreshold = 1
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
					if scheme == "slip039" {
						fmt.Println("2. Enter BIP-39 mnemonic phrase")
						fmt.Println("3. Enter raw secret (hex or text)")
					} else {
						fmt.Println("2. Enter raw secret (hex or text)")
					}
					fmt.Print("\nChoice [1]: ")

					reader := bufio.NewReader(os.Stdin)
					input, _ := reader.ReadString('\n')
					choice := strings.TrimSpace(input)
					
					// Only take first character to prevent mnemonic leakage
					if len(choice) > 1 {
						choice = string(choice[0])
						fmt.Printf("(Using choice: %s)\n\n", choice)
					}

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
					} else if choice == "2" && scheme == "slip039" {
						// BIP-39 mnemonic input (SLIP-0039 only)
						for {
							mnemonicInput, err := readMnemonicWithSmartStars("Enter BIP-39 mnemonic: ")
							if err != nil {
								return err
							}

							// Validate BIP-39 mnemonic
							m, err := mnemonic.FromWords(mnemonicInput)
							if err != nil {
								red := color.New(color.FgRed, color.Bold)
								red.Println("\n❌ Invalid BIP-39 mnemonic phrase")
								fmt.Println("\nPlease check that:")
								fmt.Println("• You entered all words correctly (typically 12, 18, or 24 words)")
								fmt.Println("• Words are separated by single spaces")
								fmt.Println("• All words are from the BIP-39 word list")
								fmt.Println("\nTry again or press Ctrl+C to exit.")
								continue // Try mnemonic input again
							}
							
							// Convert BIP-39 to BIP-32 master seed (SLIP-0039 standard compliance)
							// Per SLIP-0039 spec: "use the BIP-0032 master seed as the SLIP-0039 master secret"
							seed := m.Seed()
							
							// Use the first 32 bytes as the master secret (256-bit)
							// This is the seed that would be input to HMAC-SHA512 for BIP-32 derivation
							if len(seed) >= 32 {
								masterSecret = seed[:32]
							} else {
								masterSecret = seed
								// Pad to minimum 16 bytes if needed
								for len(masterSecret) < 16 {
									masterSecret = append(masterSecret, 0)
								}
							}

							fmt.Println("\n✓ Converted BIP-39 to BIP-32 master seed (SLIP-0039 compliant)")
							fmt.Printf("   Master seed: %x\n", masterSecret)
							break
						}
						break
					} else if (choice == "3" && scheme == "slip039") || (choice == "2" && scheme == "pvss") {
						// Raw secret input
						secret, err := readSecretInteractive()
						if err != nil {
							return err
						}

						// Ensure reasonable length
						if len(secret) > 32 {
							yellow := color.New(color.FgYellow)
							yellow.Printf("⚠️  Secret is %d bytes, truncating to 32 bytes for %s\n", len(secret), scheme)
							secret = secret[:32]
						}

						masterSecret = secret
						break
					} else {
						red := color.New(color.FgRed)
						red.Printf("❌ Invalid choice: %s\n\n", choice)
						continue
					}
				}
			}

			// Get passphrase if not provided (SLIP-0039 only)
			if scheme == "slip039" && passphrase == "" && !cmd.Flags().Changed("passphrase") {
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
			
			// Set passphrase in config
			config.Passphrase = passphrase

			// Split the secret using the unified interface
			shares, err := secretsharing.Split(masterSecret, config)
			if err != nil {
				return fmt.Errorf("failed to split secret: %w", err)
			}

			// Display results (always show unless --no-display is used)
			if !noFiles || outputFile == "" {
				displayShares(shares, scheme)
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

				return saveSharesToFile(shares, outputFile)
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

	cmd.Flags().StringVarP(&scheme, "scheme", "s", "slip039", "Secret sharing scheme (slip039, pvss)")
	cmd.Flags().StringVar(&curveType, "curve", "p256", "Elliptic curve for PVSS (p256 only)")
	cmd.Flags().IntVarP(&threshold, "threshold", "t", 0, "Member threshold for simple mode")
	cmd.Flags().IntVarP(&shares, "shares", "n", 0, "Number of shares for simple mode")
	cmd.Flags().IntVar(&groupThreshold, "group-threshold", 0, "Number of groups required (SLIP-0039 advanced mode)")
	cmd.Flags().StringVar(&groupsSpec, "groups", "", "Groups specification for SLIP-0039 (e.g., '2/3,3/5')")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Passphrase for encryption (SLIP-0039 only)")
	cmd.Flags().StringVar(&secretHex, "secret", "", "Master secret in hex")
	cmd.Flags().IntVarP(&secretLength, "length", "l", 0, "Generate random secret of specified bytes (16 or 32)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output shares to file (SECURITY RISK - use only for immediate printing)")
	cmd.Flags().BoolVar(&noFiles, "no-files", false, "Never save to files (display only)")

	return cmd
}

// displayShares displays shares for any supported scheme
func displayShares(shares []secretsharing.Share, scheme string) {
	if len(shares) == 0 {
		return
	}

	info := shares[0].Info
	cyan := color.New(color.FgCyan, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	yellow := color.New(color.FgYellow)

	fmt.Println()
	cyan.Printf("=== %s SECRET SHARES ===\n", strings.ToUpper(scheme))
	fmt.Println()

	// Display configuration info
	white.Printf("Configuration: %d-of-%d shares", 
		info.MemberThreshold, len(shares))
	if info.GroupCount > 1 {
		fmt.Printf(" (%d groups, %d required)", info.GroupCount, info.GroupThreshold)
	}
	fmt.Printf(" | Scheme: %s\n", strings.ToUpper(scheme))
	if scheme == "pvss" {
		fmt.Printf("Curve: P-256 | ")
		yellow.Println("✓ Publicly Verifiable")
	} else {
		yellow.Printf("Identifier: %s\n", info.Identifier)
	}
	fmt.Println()

	// Display shares
	for i, share := range shares {
		fmt.Printf("Share %d", i+1)
		if share.Info.GroupCount > 1 {
			fmt.Printf(" (Group %d, Member %d)", share.Info.GroupIndex, share.Info.MemberIndex)
		}
		fmt.Println(":")
		
		if scheme == "slip039" && share.Mnemonic != "" {
			// Display SLIP-0039 mnemonic
			fmt.Printf("  %s\n", share.Mnemonic)
		} else if scheme == "pvss" {
			// Display PVSS share as hex (could be enhanced with custom encoding)
			fmt.Printf("  PVSS:%s:%d:%d:%x\n", 
				share.Info.Identifier, 
				share.Info.GroupIndex, 
				share.Info.MemberIndex,
				share.Data)
		}
		fmt.Println()
	}

	// Security warnings
	red := color.New(color.FgRed, color.Bold)
	red.Println("🔒 SECURITY REMINDERS:")
	fmt.Println("• Write down these shares on paper and store in separate secure locations")
	fmt.Println("• Never store shares digitally or take screenshots")
	if scheme == "slip039" {
		fmt.Printf("• You need %d shares to recover your secret\n", info.MemberThreshold)
		if info.GroupCount > 1 {
			fmt.Printf("• You need shares from %d different groups\n", info.GroupThreshold)
		}
	} else if scheme == "pvss" {
		fmt.Printf("• You need %d shares to recover your secret\n", info.MemberThreshold)
		fmt.Println("• PVSS shares can be publicly verified for authenticity")
	}
}

// saveSharesToFile saves shares to a JSON file
func saveSharesToFile(shares []secretsharing.Share, filename string) error {
	type ShareFile struct {
		Scheme         string                      `json:"scheme"`
		GroupThreshold int                         `json:"group_threshold"`
		Shares         []secretsharing.Share       `json:"shares"`
		CreatedAt      string                      `json:"created_at"`
	}

	if len(shares) == 0 {
		return fmt.Errorf("no shares to save")
	}

	data := ShareFile{
		Scheme:         string(shares[0].Info.Scheme),
		GroupThreshold: shares[0].Info.GroupThreshold,
		Shares:         shares,
		CreatedAt:      fmt.Sprintf("%d", os.Getpid()), // Simple timestamp
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

// Legacy function - kept for backward compatibility
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
