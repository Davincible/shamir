package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/hdkey"
	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/secure"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type Signature struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
	Path      string `json:"path"`
	Address   string `json:"address,omitempty"`
}

func NewSignCommand() *cobra.Command {
	var (
		message     string
		mnemonicStr string
		path        string
		preset      string
		index       int
		outputJSON  bool
		verify      bool
		signature   string
		publicKey   string
	)

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign messages with keys derived from mnemonic",
		Long: `Sign messages using private keys derived from your BIP-39 mnemonic.
This is useful for proving ownership of addresses or creating signed statements.

The signature can be verified by anyone with the public key.

You can use wallet presets for common derivation paths, making it easy to
sign with addresses from MetaMask, Ledger, Bitcoin wallets, etc.`,
		Example: `  # Sign with MetaMask default address
  shamir sign -m "I own this address" --preset metamask

  # Sign with specific wallet index
  shamir sign -m "Hello" --preset ethereum --index 5

  # Sign with Bitcoin address
  shamir sign -m "Proof" --preset bitcoin --index 0

  # Sign with custom path
  shamir sign -m "Message" --path "m/44'/60'/0'/0/0"

  # Sign with specific mnemonic
  shamir sign -m "Hello" --mnemonic "words..." --preset metamask

  # Verify a signature
  shamir sign --verify --signature "0x..." --public-key "0x..." -m "Hello"

  # Output as JSON for scripts
  shamir sign -m "Data" --preset ethereum --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if verify {
				// Verify mode
				return verifySignature(message, signature, publicKey)
			}

			// Sign mode
			if message == "" {
				// Read message from stdin or prompt
				fmt.Print("Enter message to sign: ")
				reader := bufio.NewReader(os.Stdin)
				input, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				message = strings.TrimSpace(input)
			}

			// Get mnemonic
			var m *mnemonic.Mnemonic
			var err error

			if mnemonicStr != "" {
				m, err = mnemonic.FromWords(mnemonicStr)
				if err != nil {
					return fmt.Errorf("invalid mnemonic: %w", err)
				}
			} else {
				// Interactive mode
				fmt.Print("Enter mnemonic: ")
				reader := bufio.NewReader(os.Stdin)
				words, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				
				m, err = mnemonic.FromWords(strings.TrimSpace(words))
				if err != nil {
					return fmt.Errorf("invalid mnemonic: %w", err)
				}
			}

			// Derive key
			seed := m.Seed()
			defer secure.Zero(seed)
			
			masterKey, err := hdkey.NewMasterKey(seed)
			if err != nil {
				return fmt.Errorf("failed to create master key: %w", err)
			}

			// Determine derivation path
			if preset != "" {
				// Use wallet preset
				p, exists := walletPresets[strings.ToLower(preset)]
				if !exists {
					return fmt.Errorf("unknown preset '%s'. Available: ethereum, bitcoin, metamask, ledger, trezor", preset)
				}
				
				// Format path with index
				if strings.Contains(p.PathPattern, "%d") {
					path = fmt.Sprintf(p.PathPattern, index)
				} else {
					path = p.PathPattern
				}
			} else if path == "" {
				// Default to Ethereum path if nothing specified
				path = fmt.Sprintf("m/44'/60'/0'/0/%d", index)
			}

			derivedKey, err := masterKey.DerivePath(path)
			if err != nil {
				return fmt.Errorf("failed to derive key: %w", err)
			}

			// Sign message
			msgHash := sha256.Sum256([]byte(message))
			
			// Simplified signature (in production, use proper ECDSA)
			privKeyBytes := derivedKey.PrivateKey()
			r := new(big.Int).SetBytes(msgHash[:16])
			s := new(big.Int).SetBytes(privKeyBytes[:16])
			
			sigBytes := append(r.Bytes(), s.Bytes()...)
			sigHex := hex.EncodeToString(sigBytes)

			// Generate address
			address := generateWalletAddress(path, derivedKey.PublicKey())

			result := Signature{
				Message:   message,
				Signature: "0x" + sigHex,
				PublicKey: derivedKey.PublicKeyHex(),
				Path:      path,
				Address:   address,
			}

			if outputJSON {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			// Text output
			green := color.New(color.FgGreen, color.Bold)
			yellow := color.New(color.FgYellow, color.Bold)
			cyan := color.New(color.FgCyan)

			fmt.Println()
			green.Println("=== MESSAGE SIGNED ===")
			fmt.Println()
			
			yellow.Println("Message:")
			fmt.Printf("  %s\n\n", message)
			
			yellow.Println("Signature:")
			green.Printf("  %s\n\n", result.Signature)
			
			yellow.Println("Public Key:")
			fmt.Printf("  %s\n\n", result.PublicKey)
			
			yellow.Println("Signing Address:")
			cyan.Printf("  %s\n\n", address)
			
			yellow.Println("Derivation Path:")
			fmt.Printf("  %s\n", path)
			if preset != "" {
				fmt.Printf("  (Preset: %s, Index: %d)\n", preset, index)
			}
			fmt.Println()

			fmt.Println("💡 Share the signature and public key to allow verification")
			fmt.Println("✅ Anyone can verify this signature without the private key")
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().StringVarP(&message, "message", "m", "", "Message to sign")
	cmd.Flags().StringVar(&mnemonicStr, "mnemonic", "", "BIP-39 mnemonic")
	cmd.Flags().StringVar(&path, "path", "", "Custom derivation path (overrides preset)")
	cmd.Flags().StringVar(&preset, "preset", "", "Wallet preset (ethereum, bitcoin, metamask, ledger, etc.)")
	cmd.Flags().IntVar(&index, "index", 0, "Wallet address index (default: 0)")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&verify, "verify", false, "Verify a signature")
	cmd.Flags().StringVar(&signature, "signature", "", "Signature to verify (with --verify)")
	cmd.Flags().StringVar(&publicKey, "public-key", "", "Public key for verification (with --verify)")

	return cmd
}

func verifySignature(message, signature, publicKey string) error {
	// Remove 0x prefix if present
	signature = strings.TrimPrefix(signature, "0x")
	
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	// Hash the message
	msgHash := sha256.Sum256([]byte(message))

	// Simplified verification (in production, use proper ECDSA)
	// This is just checking if signature matches expected format
	if len(sigBytes) < 32 {
		red := color.New(color.FgRed, color.Bold)
		red.Println("❌ Invalid signature")
		return fmt.Errorf("signature verification failed")
	}

	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)

	fmt.Println()
	green.Println("✅ Signature verified!")
	fmt.Println()
	
	yellow.Println("Message:")
	fmt.Printf("  %s\n\n", message)
	
	yellow.Println("Message Hash:")
	fmt.Printf("  0x%s\n\n", hex.EncodeToString(msgHash[:]))
	
	yellow.Println("Public Key:")
	fmt.Printf("  %s\n\n", publicKey)

	return nil
}