package cli

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/crypto/shamir"
	"github.com/Davincible/shamir/pkg/secure"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type ShareFormats struct {
	Hex      string `json:"hex"`
	Base64   string `json:"base64"`
	Mnemonic string `json:"mnemonic,omitempty"`
}

type SplitResult struct {
	Shares    []ShareFormats `json:"shares"`
	Threshold int            `json:"threshold"`
	Total     int            `json:"total"`
	// Legacy field for backward compatibility
	SharesHex []string `json:"shares_hex,omitempty"`
}

func NewSplitCommand() *cobra.Command {
	var (
		parts        int
		threshold    int
		useStdin     bool
		outputJSON   bool
		fromMnemonic bool
		outputFile   string
	)

	cmd := &cobra.Command{
		Use:   "split",
		Short: "Split a secret into multiple shares",
		Long: `Split a secret (seed phrase or raw data) into multiple shares using
Shamir's Secret Sharing. The secret can be reconstructed from any
threshold number of shares.

Output formats:
- Hex encoding (for technical use and debugging)
- Base64 encoding (for compact storage and transmission)

Note: Shares cannot be converted to meaningful BIP39 mnemonics as they
contain cryptographic overhead and aren't valid entropy.`,
		Example: `  # Split a mnemonic into 5 shares with threshold 3
  shamir split --parts 5 --threshold 3 --mnemonic

  # Split raw data from stdin
  echo "secret data" | shamir split --parts 3 --threshold 2 --stdin

  # Output shares to file
  shamir split --parts 5 --threshold 3 --output shares.json

  # Each share is displayed in hex and base64 formats`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateSplitParams(parts, threshold); err != nil {
				return err
			}

			outputJSON, _ = cmd.Flags().GetBool("json")

			var secret []byte
			var err error

			if useStdin {
				secret, err = readFromStdin()
			} else if fromMnemonic {
				secret, err = readMnemonicInteractive()
			} else {
				secret, err = readSecretInteractive()
			}

			if err != nil {
				return fmt.Errorf("failed to read secret: %w", err)
			}

			defer secure.Zero(secret)

			shares, err := shamir.Split(secret, shamir.Config{
				Parts:     parts,
				Threshold: threshold,
			})
			if err != nil {
				return fmt.Errorf("failed to split secret: %w", err)
			}

			result := SplitResult{
				Shares:    make([]ShareFormats, len(shares)),
				Threshold: threshold,
				Total:     parts,
				SharesHex: make([]string, len(shares)), // For backward compatibility
			}

			for i, share := range shares {
				hexStr := hex.EncodeToString(share.Data)
				base64Str := base64.StdEncoding.EncodeToString(share.Data)
				
				var mnemonicStr string
				if fromMnemonic {
					// When input was a mnemonic, try to create a readable mnemonic from share data
					// Note: Since shares have cryptographic overhead (16→17 bytes), we pad to nearest valid size
					shareData := share.Data
					if len(shareData) == 17 {
						// Pad 17 bytes to 20 bytes (15 word mnemonic)
						paddedData := make([]byte, 20)
						copy(paddedData, shareData)
						if m, err := mnemonic.FromEntropy(paddedData); err == nil {
							mnemonicStr = m.Words()
						}
					} else if len(shareData) >= 16 && len(shareData) <= 32 && len(shareData)%4 == 0 {
						// Use data directly if it's already valid BIP39 entropy length
						if m, err := mnemonic.FromEntropy(shareData); err == nil {
							mnemonicStr = m.Words()
						}
					}
				}

				result.Shares[i] = ShareFormats{
					Hex:      hexStr,
					Base64:   base64Str,
					Mnemonic: mnemonicStr,
				}
				
				// For backward compatibility
				result.SharesHex[i] = hexStr
			}

			if outputFile != "" {
				return saveToFile(result, outputFile)
			}

			if outputJSON {
				return outputJSONResult(result)
			}

			return outputTextResult(result)
		},
	}

	cmd.Flags().IntVarP(&parts, "parts", "n", 5, "Total number of shares to create")
	cmd.Flags().IntVarP(&threshold, "threshold", "t", 3, "Minimum shares needed to reconstruct")
	cmd.Flags().BoolVar(&useStdin, "stdin", false, "Read secret from stdin")
	cmd.Flags().BoolVar(&fromMnemonic, "mnemonic", false, "Input is a BIP39 mnemonic phrase")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output shares to file")

	return cmd
}

func validateSplitParams(parts, threshold int) error {
	config := shamir.Config{
		Parts:     parts,
		Threshold: threshold,
	}
	return config.Validate()
}

func readFromStdin() ([]byte, error) {
	scanner := bufio.NewScanner(os.Stdin)
	var lines []string

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return []byte(strings.Join(lines, "\n")), nil
}

func readMnemonicInteractive() ([]byte, error) {
	fmt.Print("Enter your mnemonic phrase (12-24 words): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	input = strings.TrimSpace(input)

	m, err := mnemonic.FromWords(input)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	fmt.Print("Enter passphrase (optional, press Enter to skip): ")
	
	// Try to read passphrase securely, but fallback to regular input if no TTY
	var passphrase []byte
	if term.IsTerminal(int(syscall.Stdin)) {
		passphrase, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, err
		}
		fmt.Println()
	} else {
		// Fallback to regular input when not in a terminal
		passphraseStr, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		passphrase = []byte(strings.TrimSpace(passphraseStr))
	}

	if len(passphrase) > 0 {
		m.SetPassphrase(string(passphrase))
		secure.Zero(passphrase)
	}

	return m.Entropy()
}

func readSecretInteractive() ([]byte, error) {
	fmt.Print("Enter your secret: ")

	secret, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	fmt.Println()

	if len(secret) == 0 {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	return secret, nil
}

func saveToFile(result SplitResult, filename string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Shares saved to %s\n", filename)
	return nil
}

func outputJSONResult(result SplitResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputTextResult(result SplitResult) error {
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	blue := color.New(color.FgBlue, color.Bold)

	fmt.Println()
	yellow.Println("=== SHAMIR SECRET SHARES ===")
	fmt.Println()

	green.Printf("Created %d shares with threshold %d\n", result.Total, result.Threshold)
	fmt.Printf("Any %d shares can reconstruct the original secret\n\n", result.Threshold)

	red.Println("⚠️  SECURITY WARNING:")
	fmt.Println("- Store each share in a different secure location")
	fmt.Println("- Never store shares together or electronically")
	fmt.Println("- Each share should be treated as highly sensitive")
	fmt.Println()

	for i, share := range result.Shares {
		fmt.Printf("Share %d of %d:\n", i+1, result.Total)
		fmt.Println()
		
		cyan.Print("  Hex:    ")
		fmt.Println(share.Hex)
		
		blue.Print("  Base64: ")
		fmt.Println(share.Base64)
		
		if share.Mnemonic != "" {
			green.Print("  Words:  ")
			fmt.Println(share.Mnemonic)
		}
		
		fmt.Println()
	}

	yellow.Println("=== END OF SHARES ===")
	fmt.Println()
	fmt.Println("Note: Both formats (hex, base64) represent the same share.")
	fmt.Println("Use either format when reconstructing the secret.")

	return nil
}
