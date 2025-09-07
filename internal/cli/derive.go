package cli

import (
	"bufio"
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
	"golang.org/x/term"
)

type DeriveResult struct {
	Path      string `json:"path"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address,omitempty"`
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

			result := DeriveResult{
				Path:      path,
				PublicKey: derivedKey.PublicKeyHex(),
			}

			if outputJSON {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			return outputDeriveText(derivedKey, showPrivate)
		},
	}

	cmd.Flags().StringVarP(&path, "path", "p", "", "BIP32 derivation path")
	cmd.Flags().Uint32VarP(&account, "account", "a", 0, "Account number for Ledger path")
	cmd.Flags().BoolVar(&showPrivate, "show-private", false, "Show private key (DANGEROUS)")

	return cmd
}

func outputDeriveText(key *hdkey.HDKey, showPrivate bool) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)

	fmt.Println()
	green.Println("=== DERIVED KEY ===")
	fmt.Println()

	yellow.Println("Derivation Path:")
	fmt.Printf("  %s\n\n", key.Path())

	yellow.Println("Public Key:")
	fmt.Printf("  %s\n\n", key.PublicKeyHex())

	yellow.Println("Extended Public Key:")
	fmt.Printf("  %s\n\n", key.ExtendedPublicKey())

	if showPrivate {
		red.Println("⚠️  PRIVATE KEY (KEEP SECRET):")
		fmt.Printf("  %s\n\n", key.PrivateKeyHex())

		red.Println("⚠️  Extended Private Key:")
		fmt.Printf("  %s\n\n", key.ExtendedPrivateKey())
	}

	green.Println("=== END ===")

	return nil
}
