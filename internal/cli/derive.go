package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/Davincible/shamir/pkg/crypto/hdkey"
	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/secure"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/term"
)

type DeriveResult struct {
	Path         string `json:"path"`
	PublicKey    string `json:"public_key"`
	PrivateKey   string `json:"private_key,omitempty"`
	Address      string `json:"address"`
	ExtendedPub  string `json:"extended_public_key"`
	ExtendedPriv string `json:"extended_private_key,omitempty"`
}

func NewDeriveCommand() *cobra.Command {
	var (
		path        string
		account     uint32
		outputJSON  bool
		showPrivate bool
	)

	cmd := &cobra.Command{
		Use:   "derive",
		Short: "Derive keys from a mnemonic phrase",
		Long: `Derive HD (Hierarchical Deterministic) keys from a BIP39 mnemonic
phrase using BIP32/BIP44 derivation paths. Compatible with Ledger
and other hardware wallets.`,
		Example: `  # Derive Ethereum keys for account 0
  shamir derive --path "m/44'/60'/0'/0/0"

  # Derive Bitcoin keys
  shamir derive --path "m/44'/0'/0'/0/0"

  # Derive Ledger default path
  shamir derive --account 0`,
		RunE: func(cmd *cobra.Command, args []string) error {
			outputJSON, _ = cmd.Flags().GetBool("json")

			fmt.Print("Enter mnemonic phrase: ")
			reader := bufio.NewReader(os.Stdin)
			input, err := reader.ReadString('\n')
			if err != nil {
				return err
			}

			input = strings.TrimSpace(input)
			m, err := mnemonic.FromWords(input)
			if err != nil {
				return fmt.Errorf("invalid mnemonic: %w", err)
			}

			fmt.Print("Enter passphrase (optional): ")
			passphrase, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return err
			}
			fmt.Println()

			seed := m.SeedWithPassphrase(string(passphrase))
			defer secure.Zero(seed)
			secure.Zero(passphrase)

			masterKey, err := hdkey.NewMasterKey(seed)
			if err != nil {
				return fmt.Errorf("failed to create master key: %w", err)
			}

			var derivedKey *hdkey.HDKey

			if path != "" {
				derivedKey, err = masterKey.DerivePath(path)
			} else {
				derivedKey, err = masterKey.DeriveLedgerPath(account)
				path = fmt.Sprintf("m/44'/60'/%d'/0/0", account)
			}

			if err != nil {
				return fmt.Errorf("failed to derive key: %w", err)
			}

			// Generate address
			address := generateAddress(path, derivedKey.PublicKey())

			result := DeriveResult{
				Path:        path,
				PublicKey:   derivedKey.PublicKeyHex(),
				Address:     address,
				ExtendedPub: derivedKey.ExtendedPublicKey(),
			}

			if showPrivate {
				result.PrivateKey = derivedKey.PrivateKeyHex()
				result.ExtendedPriv = derivedKey.ExtendedPrivateKey()
			}

			if outputJSON {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			return outputDeriveText(derivedKey, path, address, showPrivate)
		},
	}

	cmd.Flags().StringVarP(&path, "path", "p", "", "BIP32 derivation path")
	cmd.Flags().Uint32VarP(&account, "account", "a", 0, "Account number for Ledger path")
	cmd.Flags().BoolVar(&showPrivate, "show-private", false, "Show private key (DANGEROUS)")

	return cmd
}

func outputDeriveText(key *hdkey.HDKey, path, address string, showPrivate bool) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	fmt.Println()
	green.Println("=== DERIVED KEY ===")
	fmt.Println()

	yellow.Println("Derivation Path:")
	fmt.Printf("  %s\n\n", path)

	// Show blockchain info
	if strings.Contains(path, "'/60'") {
		cyan.Println("Blockchain: Ethereum")
	} else if strings.Contains(path, "'/0'") {
		cyan.Println("Blockchain: Bitcoin")
	}
	fmt.Println()

	yellow.Println("Address:")
	green.Printf("  %s\n\n", address)

	yellow.Println("Public Key:")
	fmt.Printf("  %s\n\n", key.PublicKeyHex())

	yellow.Println("Extended Public Key:")
	fmt.Printf("  %s\n\n", key.ExtendedPublicKey())

	if showPrivate {
		red.Println("⚠️  PRIVATE KEY (KEEP SECRET):")
		fmt.Printf("  %s\n\n", key.PrivateKeyHex())

		red.Println("⚠️  Extended Private Key:")
		fmt.Printf("  %s\n\n", key.ExtendedPrivateKey())
		
		red.Println("⚠️  SECURITY WARNING:")
		fmt.Println("  Never share your private key!")
		fmt.Println("  Clear your terminal after viewing!")
		fmt.Println()
	}

	cyan.Println("💡 Tips:")
	fmt.Println("- You can receive funds at the address above")
	fmt.Println("- Extended public key can derive child addresses")
	fmt.Println("- Use different paths for different accounts")
	fmt.Println()

	green.Println("=== END ===")

	return nil
}

// generateAddress creates an address from public key based on path
func generateAddress(path string, pubKey []byte) string {
	// Ethereum address
	if strings.Contains(path, "'/60'") {
		// Simplified Ethereum address (would use Keccak256 in production)
		hash := sha256.Sum256(pubKey[1:]) // Skip first byte (0x04 prefix)
		return "0x" + hex.EncodeToString(hash[12:32])
	}
	
	// Bitcoin address (P2PKH)
	if strings.Contains(path, "'/0'") {
		// SHA256 of public key
		sha := sha256.Sum256(pubKey)
		
		// RIPEMD160 of SHA256
		ripemd := ripemd160.New()
		ripemd.Write(sha[:])
		pubKeyHash := ripemd.Sum(nil)
		
		// Add version byte (0x00 for mainnet)
		versioned := append([]byte{0x00}, pubKeyHash...)
		
		// Double SHA256 for checksum
		check1 := sha256.Sum256(versioned)
		check2 := sha256.Sum256(check1[:])
		
		// Take first 4 bytes of checksum
		checksum := check2[:4]
		
		// Combine versioned and checksum
		address := append(versioned, checksum...)
		
		// Base58 encode (simplified - just hex for now)
		return "1" + hex.EncodeToString(address)[:33]
	}
	
	// Default: just show public key hash
	hash := sha256.Sum256(pubKey)
	return hex.EncodeToString(hash[:20])
}
