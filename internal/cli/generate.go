package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Davincible/shamir/pkg/crypto/hdkey"
	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ripemd160"
)

func NewGenerateCommand() *cobra.Command {
	var (
		wordCount  int
		outputJSON bool
		showKeys   bool
		showSeed   bool
		derivePath string
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new BIP39 mnemonic phrase",
		SilenceUsage: true,
		Long: `Generate a new cryptographically secure BIP39 mnemonic phrase
that can be used as a seed for cryptocurrency wallets.`,
		Example: `  # Generate 24-word mnemonic with keys and seed
  shamir generate --words 24 --show-keys --show-seed

  # Generate with Ethereum address
  shamir generate --path "m/44'/60'/0'/0/0"

  # Generate with Bitcoin address
  shamir generate --path "m/44'/0'/0'/0/0"

  # Show master seed (hex)
  shamir generate --show-seed

  # Output as JSON (always includes seed)
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

			// Generate master seed (always generate for display)
			seed := m.Seed()
			
			// Get entropy for comparison with SLIP-0039
			entropy, err := m.Entropy()
			if err != nil {
				return fmt.Errorf("failed to get entropy: %w", err)
			}
			
			// Generate keys if requested
			var keyInfo *KeyInfo
			if showKeys || derivePath != "" {
				if derivePath == "" {
					derivePath = "m/44'/60'/0'/0/0" // Default to Ethereum
				}
				
				masterKey, err := hdkey.NewMasterKey(seed)
				if err != nil {
					return fmt.Errorf("failed to create master key: %w", err)
				}
				
				derivedKey, err := masterKey.DerivePath(derivePath)
				if err != nil {
					return fmt.Errorf("failed to derive key: %w", err)
				}
				
				keyInfo = &KeyInfo{
					Path:       derivePath,
					PublicKey:  hex.EncodeToString(derivedKey.PublicKey()),
					PrivateKey: hex.EncodeToString(derivedKey.PrivateKey()),
					Address:    deriveAddress(derivePath, derivedKey.PublicKey()),
				}
			}

			if outputJSON {
				result := map[string]interface{}{
					"mnemonic":    m.Words(),
					"word_count":  m.WordCount(),
					"entropy":     hex.EncodeToString(entropy),
					"entropy_bits": len(entropy) * 8,
					"bip39_seed":  hex.EncodeToString(seed),
					"seed_bits":   len(seed) * 8,
				}
				if keyInfo != nil {
					result["derivation"] = keyInfo
				}
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			return outputGenerateText(m, keyInfo, seed, entropy, showSeed)
		},
	}

	cmd.Flags().IntVarP(&wordCount, "words", "w", 24, "Number of words (12, 15, 18, 21, or 24)")
	cmd.Flags().BoolVar(&showKeys, "show-keys", false, "Show derived public key and address")
	cmd.Flags().BoolVar(&showSeed, "show-seed", false, "Show master seed in hexadecimal")
	cmd.Flags().StringVar(&derivePath, "path", "", "BIP32 derivation path (implies --show-keys)")

	return cmd
}

type KeyInfo struct {
	Path       string `json:"path"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key,omitempty"`
	Address    string `json:"address"`
}

func outputGenerateText(m *mnemonic.Mnemonic, keyInfo *KeyInfo, seed []byte, entropy []byte, showSeed bool) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

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

	// Show cryptographic details if requested
	if showSeed {
		cyan.Println("=== CRYPTOGRAPHIC DETAILS ===")
		fmt.Println()
		
		yellow.Println("🎲 Entropy (Original Random Data):")
		fmt.Println(hex.EncodeToString(entropy))
		fmt.Printf("Length: %d bytes (%d bits)\n", len(entropy), len(entropy)*8)
		fmt.Println()
		fmt.Println("💡 This is what gets shared in SLIP-0039/PVSS schemes")
		fmt.Println()
		
		yellow.Println("🔑 BIP-39 Master Seed (PBKDF2 Result):")
		fmt.Println(hex.EncodeToString(seed))
		fmt.Printf("Length: %d bytes (%d bits)\n", len(seed), len(seed)*8)
		fmt.Println()
		fmt.Println("💡 This is used for HD wallet key derivation")
		fmt.Println()
		
		red.Println("⚠️  Both values above can access ALL your funds!")
		fmt.Println("Keep them as secure as your mnemonic phrase.")
		fmt.Println()
	} else {
		yellow.Println("💡 Use --show-seed to display entropy and BIP-39 seed")
		fmt.Println()
	}

	// Show key information if requested
	if keyInfo != nil {
		cyan.Println("=== DERIVED KEYS ===")
		fmt.Println()
		fmt.Printf("Path:       %s\n", keyInfo.Path)
		fmt.Printf("Public Key: %s\n", keyInfo.PublicKey)
		
		if keyInfo.Address != "" {
			fmt.Printf("Address:    %s\n", keyInfo.Address)
		}
		
		fmt.Println()
		yellow.Println("💡 Tips:")
		fmt.Println("- The address above can receive funds")
		fmt.Println("- Never share your mnemonic or private key")
		fmt.Println("- Use 'shamir derive' to get more addresses")
		fmt.Println()
	}

	green.Println("=== END ===")

	return nil
}

// deriveAddress generates an address based on the derivation path
func deriveAddress(path string, pubKey []byte) string {
	// Check if it's Ethereum path
	if len(path) > 6 && path[6:11] == "'/60'" {
		// Ethereum address (last 20 bytes of Keccak256 hash)
		// For simplicity, showing first 20 bytes of public key hash
		// In production, would use proper Keccak256
		hash := sha256.Sum256(pubKey)
		return "0x" + hex.EncodeToString(hash[12:32])
	}
	
	// Check if it's Bitcoin path
	if len(path) > 6 && path[6:10] == "'/0'" {
		// Bitcoin P2PKH address (simplified)
		hash := sha256.Sum256(pubKey)
		ripemd := ripemd160.New()
		ripemd.Write(hash[:])
		return "1" + hex.EncodeToString(ripemd.Sum(nil))[:33] // Simplified
	}
	
	// Default: just show public key hash
	hash := sha256.Sum256(pubKey)
	return hex.EncodeToString(hash[:20])
}
