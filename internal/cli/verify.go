package cli

import (
	"fmt"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/crypto/slip039"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func NewVerifyCommand() *cobra.Command {
	var (
		typeMnemonic string
	)

	cmd := &cobra.Command{
		Use:   "verify [mnemonic]",
		Short: "Verify the integrity of a mnemonic",
		Long: `Verify that a mnemonic is valid.
Supports both BIP-39 mnemonics and SLIP-0039 shares.`,
		Example: `  # Verify a BIP-39 mnemonic
  shamir verify "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

  # Verify a SLIP-0039 share
  shamir verify "academic acid acne ......" --type slip039`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := strings.TrimSpace(args[0])

			green := color.New(color.FgGreen, color.Bold)
			yellow := color.New(color.FgYellow)
			red := color.New(color.FgRed, color.Bold)

			// Auto-detect type if not specified
			if typeMnemonic == "" {
				words := strings.Fields(input)
				if len(words) == 20 || len(words) == 33 {
					typeMnemonic = "slip039"
				} else {
					typeMnemonic = "bip39"
				}
			}

			fmt.Println()

			if typeMnemonic == "slip039" {
				// Verify SLIP-0039 share
				if err := slip039.ValidateMnemonic(input); err != nil {
					red.Println("✗ Invalid SLIP-0039 share")
					fmt.Printf("Error: %v\n", err)
					return nil
				}

				green.Println("✓ Valid SLIP-0039 share")
				fmt.Println()

				// Get share info
				info, err := slip039.GetShareInfo(input)
				if err == nil {
					yellow.Println("Share details:")
					fmt.Printf("  Identifier: %d\n", info.Identifier)
					fmt.Printf("  Group: %d of %d\n", info.GroupIndex, info.GroupCount)
					fmt.Printf("  Group threshold: %d\n", info.GroupThreshold)
					fmt.Printf("  Member: %d\n", info.MemberIndex)
					fmt.Printf("  Member threshold: %d\n", info.MemberThreshold)
					if info.Extendable {
						fmt.Println("  Extendable: Yes")
					}
				}
			} else {
				// Verify BIP-39 mnemonic
				m, err := mnemonic.FromWords(input)
				if err != nil {
					red.Println("✗ Invalid BIP-39 mnemonic")
					fmt.Printf("Error: %v\n", err)
					return nil
				}

				green.Println("✓ Valid BIP-39 mnemonic")
				fmt.Println()

				yellow.Println("Mnemonic details:")
				fmt.Printf("  Word count: %d\n", m.WordCount())
				// Calculate entropy and checksum bits from word count
				entropyBits := (m.WordCount() * 11 * 32) / 33
				checksumBits := m.WordCount() * 11 - entropyBits
				fmt.Printf("  Entropy bits: %d\n", entropyBits)
				fmt.Printf("  Checksum bits: %d\n", checksumBits)
			}

			fmt.Println()
			return nil
		},
	}

	cmd.Flags().StringVar(&typeMnemonic, "type", "", "Mnemonic type (bip39 or slip039, auto-detected if not specified)")

	return cmd
}
