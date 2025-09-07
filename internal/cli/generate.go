package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func NewGenerateCommand() *cobra.Command {
	var (
		wordCount  int
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new BIP39 mnemonic phrase",
		Long: `Generate a new cryptographically secure BIP39 mnemonic phrase
that can be used as a seed for cryptocurrency wallets.`,
		Example: `  # Generate 24-word mnemonic
  shamir generate --words 24

  # Generate 12-word mnemonic (default)
  shamir generate

  # Output as JSON
  shamir generate --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			outputJSON, _ = cmd.Flags().GetBool("json")

			entropyBits, err := mnemonic.EntropyBitsFromWordCount(wordCount)
			if err != nil {
				return fmt.Errorf("invalid word count: %w", err)
			}

			m, err := mnemonic.NewMnemonic(entropyBits)
			if err != nil {
				return fmt.Errorf("failed to generate mnemonic: %w", err)
			}

			if outputJSON {
				result := map[string]interface{}{
					"mnemonic":   m.Words(),
					"word_count": m.WordCount(),
				}
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			return outputGenerateText(m)
		},
	}

	cmd.Flags().IntVarP(&wordCount, "words", "w", 24, "Number of words (12, 15, 18, 21, or 24)")

	return cmd
}

func outputGenerateText(m *mnemonic.Mnemonic) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)

	fmt.Println()
	green.Println("=== NEW MNEMONIC PHRASE ===")
	fmt.Println()

	red.Println("⚠️  IMPORTANT SECURITY NOTICE:")
	fmt.Println("This mnemonic phrase is your master seed. Anyone who knows this")
	fmt.Println("phrase can access all derived accounts and steal your funds.")
	fmt.Println()
	fmt.Println("- Write it down on paper (never digitally)")
	fmt.Println("- Store it in a secure location")
	fmt.Println("- Never share it with anyone")
	fmt.Println("- Consider using Shamir's Secret Sharing for backup")
	fmt.Println()

	yellow.Printf("Generated %d-word mnemonic:\n\n", m.WordCount())

	words := m.WordList()
	for i, word := range words {
		fmt.Printf("%2d. %s\n", i+1, word)
	}

	fmt.Println()
	yellow.Println("Complete phrase:")
	fmt.Println(m.Words())
	fmt.Println()

	green.Println("=== END ===")

	return nil
}
