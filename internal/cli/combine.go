package cli

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/crypto/shamir"
	"github.com/Davincible/shamir/pkg/secure"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type CombineInput struct {
	Shares []string `json:"shares"`
}

func NewCombineCommand() *cobra.Command {
	var (
		inputFile   string
		outputJSON  bool
		toMnemonic  bool
		interactive bool
	)

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combine shares to reconstruct the original secret",
		Long: `Reconstruct the original secret from a threshold number of shares
created by the split command. Requires at least the threshold number
of valid shares.

Automatically detects input formats:
- Hex encoding (e.g., 48656c6c6f20576f726c64)
- Base64 encoding (e.g., SGVsbG8gV29ybGQ=)
- BIP39 mnemonic words (e.g., abandon abandon abandon...)

Interactive mode is the default when no input method is specified.`,
		Example: `  # Combine shares interactively (default)
  shamir combine

  # Combine shares from a file
  shamir combine --input shares.json

  # Reconstruct as mnemonic
  shamir combine --mnemonic`,
		RunE: func(cmd *cobra.Command, args []string) error {
			outputJSON, _ = cmd.Flags().GetBool("json")

			var shares []shamir.Share
			var err error

			if inputFile != "" {
				shares, err = readSharesFromFile(inputFile)
			} else {
				shares, err = readSharesInteractive()
			}

			if err != nil {
				return fmt.Errorf("failed to read shares: %w", err)
			}

			if len(shares) < 2 {
				return fmt.Errorf("at least 2 shares are required")
			}

			secret, err := shamir.Combine(shares)
			if err != nil {
				return fmt.Errorf("failed to combine shares: %w", err)
			}
			defer secure.Zero(secret)

			if toMnemonic {
				return outputMnemonic(secret, outputJSON)
			}

			return outputSecret(secret, outputJSON)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Read shares from JSON file")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "Enter shares interactively")
	cmd.Flags().BoolVar(&toMnemonic, "mnemonic", false, "Output as BIP39 mnemonic phrase")

	return cmd
}

func readSharesFromFile(filename string) ([]shamir.Share, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var input struct {
		Shares []string `json:"shares"`
	}

	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return parseShares(input.Shares)
}

func readSharesInteractive() ([]shamir.Share, error) {
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)
	cyan := color.New(color.FgCyan)

	yellow.Println("Enter shares (one per line, empty line to finish):")
	fmt.Println("Accepts: hex, base64, or mnemonic formats")

	reader := bufio.NewReader(os.Stdin)
	var shareStrings []string

	for i := 1; ; i++ {
		fmt.Printf("Share %d: ", i)

		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		format := detectFormat(line)
		shareStrings = append(shareStrings, line)
		green.Printf("✓ Share %d added ", i)
		cyan.Printf("(%s format)\n", format)
	}

	return parseShares(shareStrings)
}

func detectFormat(s string) string {
	s = strings.TrimSpace(s)
	
	// Check if it's a valid hex string
	if _, err := hex.DecodeString(s); err == nil && len(s)%2 == 0 {
		return "hex"
	}
	
	// Check if it's a valid base64 string
	if _, err := base64.StdEncoding.DecodeString(s); err == nil {
		return "base64"
	}
	
	// Check if it looks like a mnemonic (multiple words)
	words := strings.Fields(s)
	if len(words) >= 3 { // At least 3 words to be considered a mnemonic
		return "mnemonic"
	}
	
	return "unknown"
}

func parseShareData(s string, format string) ([]byte, error) {
	switch format {
	case "hex":
		return hex.DecodeString(s)
	case "base64":
		return base64.StdEncoding.DecodeString(s)
	case "mnemonic":
		m, err := mnemonic.FromWords(s)
		if err != nil {
			return nil, fmt.Errorf("invalid mnemonic: %w", err)
		}
		return m.Entropy()
	default:
		return nil, fmt.Errorf("unknown format: %s", format)
	}
}

func parseShares(shareStrings []string) ([]shamir.Share, error) {
	shares := make([]shamir.Share, 0, len(shareStrings))
	shareIndex := byte(1)

	for i, s := range shareStrings {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		format := detectFormat(s)
		if format == "unknown" {
			return nil, fmt.Errorf("share %d: could not detect format (expected hex, base64, or mnemonic)", i+1)
		}

		data, err := parseShareData(s, format)
		if err != nil {
			return nil, fmt.Errorf("share %d (%s format): %w", i+1, format, err)
		}

		shares = append(shares, shamir.Share{
			Index: shareIndex,
			Data:  data,
		})
		shareIndex++
	}

	return shares, nil
}

func outputMnemonic(secret []byte, asJSON bool) error {
	m, err := mnemonic.FromEntropy(secret)
	if err != nil {
		return fmt.Errorf("failed to convert to mnemonic: %w", err)
	}

	if asJSON {
		result := map[string]interface{}{
			"mnemonic":   m.Words(),
			"word_count": m.WordCount(),
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)

	fmt.Println()
	green.Println("=== RECONSTRUCTED MNEMONIC ===")
	fmt.Println()

	words := m.WordList()
	for i, word := range words {
		fmt.Printf("%2d. %s\n", i+1, word)
	}

	fmt.Println()
	yellow.Println("Full phrase:")
	fmt.Println(m.Words())
	fmt.Println()
	green.Println("=== END ===")

	return nil
}

func outputSecret(secret []byte, asJSON bool) error {
	if asJSON {
		result := map[string]string{
			"secret": hex.EncodeToString(secret),
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	green := color.New(color.FgGreen, color.Bold)

	fmt.Println()
	green.Println("=== RECONSTRUCTED SECRET ===")
	fmt.Println()
	fmt.Println(hex.EncodeToString(secret))
	fmt.Println()
	green.Println("=== END ===")

	return nil
}
