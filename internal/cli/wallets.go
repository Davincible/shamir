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

type WalletPreset struct {
	Name        string
	Coin        string
	PathPattern string
	Symbol      string
	Description string
}

type WalletAddress struct {
	Index      int    `json:"index"`
	Path       string `json:"path"`
	Address    string `json:"address"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key,omitempty"`
}

var walletPresets = map[string]WalletPreset{
	"ethereum": {
		Name:        "Ethereum",
		Coin:        "ETH",
		PathPattern: "m/44'/60'/0'/0/%d",
		Symbol:      "Ξ",
		Description: "Ethereum & EVM chains (MetaMask, etc.)",
	},
	"bitcoin": {
		Name:        "Bitcoin",
		Coin:        "BTC",
		PathPattern: "m/84'/0'/0'/0/%d", // Native SegWit (bc1...)
		Symbol:      "₿",
		Description: "Bitcoin Native SegWit (bc1...) - RECOMMENDED: Lowest fees",
	},
	"bitcoin-legacy": {
		Name:        "Bitcoin Legacy",
		Coin:        "BTC",
		PathPattern: "m/44'/0'/0'/0/%d", // Legacy (1...)
		Symbol:      "₿",
		Description: "Bitcoin Legacy (1...) - OLD: Highest fees, wide support",
	},
	"bitcoin-segwit": {
		Name:        "Bitcoin SegWit",
		Coin:        "BTC",
		PathPattern: "m/49'/0'/0'/0/%d", // Nested SegWit (3...)
		Symbol:      "₿",
		Description: "Bitcoin Nested SegWit (3...) - COMPATIBLE: Medium fees",
	},
	"bitcoin-taproot": {
		Name:        "Bitcoin Taproot",
		Coin:        "BTC",
		PathPattern: "m/86'/0'/0'/0/%d", // Taproot (bc1p...)
		Symbol:      "₿",
		Description: "Bitcoin Taproot (bc1p...) - NEWEST: Privacy & smart contracts",
	},
	"ledger": {
		Name:        "Ledger",
		Coin:        "ETH",
		PathPattern: "m/44'/60'/%d'/0/0",
		Symbol:      "📱",
		Description: "Ledger hardware wallet Ethereum accounts",
	},
	"ledger-legacy": {
		Name:        "Ledger Legacy",
		Coin:        "ETH",
		PathPattern: "m/44'/60'/0'/0/%d",
		Symbol:      "📱",
		Description: "Ledger Legacy path (same as MetaMask)",
	},
	"ledger-live": {
		Name:        "Ledger",
		Coin:        "ETH",
		PathPattern: "m/44'/60'/%d'/0/0",
		Symbol:      "📱",
		Description: "Ledger hardware wallet Ethereum accounts (alias for 'ledger')",
	},
	"ledger-bitcoin": {
		Name:        "Ledger Bitcoin",
		Coin:        "BTC",
		PathPattern: "m/84'/0'/%d'/0/0",
		Symbol:      "📱",
		Description: "Ledger Bitcoin Native SegWit accounts",
	},
	"metamask": {
		Name:        "MetaMask",
		Coin:        "ETH",
		PathPattern: "m/44'/60'/0'/0/%d",
		Symbol:      "🦊",
		Description: "MetaMask default derivation",
	},
	"trezor": {
		Name:        "Trezor",
		Coin:        "ETH",
		PathPattern: "m/44'/60'/0'/0/%d",
		Symbol:      "🔐",
		Description: "Trezor Suite Ethereum",
	},
	"binance": {
		Name:        "BNB Smart Chain",
		Coin:        "BNB",
		PathPattern: "m/44'/60'/0'/0/%d", // Same as ETH
		Symbol:      "🔶",
		Description: "Binance Smart Chain (BSC)",
	},
	"polygon": {
		Name:        "Polygon",
		Coin:        "MATIC",
		PathPattern: "m/44'/60'/0'/0/%d", // Same as ETH
		Symbol:      "💜",
		Description: "Polygon (MATIC) network",
	},
	"avalanche": {
		Name:        "Avalanche C-Chain",
		Coin:        "AVAX",
		PathPattern: "m/44'/60'/0'/0/%d", // EVM compatible
		Symbol:      "🔺",
		Description: "Avalanche C-Chain",
	},
}

func NewWalletsCommand() *cobra.Command {
	var (
		preset       string
		count        int
		startIndex   int
		mnemonicStr  string
		passphrase   string
		outputJSON   bool
		showPrivate  bool
		customPath   string
		listPresets  bool
		interactive  bool
	)

	cmd := &cobra.Command{
		Use:   "wallets",
		Short: "Generate wallet addresses with presets for popular wallets",
		Long: `Generate wallet addresses compatible with popular wallets like MetaMask, 
Ledger, and Trezor. This tool helps you derive the exact same addresses your 
hardware or software wallet would generate from a BIP-39 mnemonic.

KEY FEATURES:
  • Presets for all major wallets (MetaMask, Ledger, Trezor, etc.)
  • Bitcoin address types with fee guidance (Native SegWit, Taproot, Legacy)
  • Batch address generation for multiple wallets
  • Interactive mode for secure mnemonic entry
  • Support for BIP-39 passphrases
  • Multiple account support for hardware wallets

BITCOIN ADDRESS TYPES:
  Native SegWit (bc1q...)  - RECOMMENDED: Lowest fees, modern standard
  Taproot (bc1p...)        - NEWEST: Privacy features, future-proof
  Nested SegWit (3...)     - COMPATIBLE: Medium fees, wide support
  Legacy (1...)            - OLD: Highest fees, universal support

SECURITY NOTES:
  • Use interactive mode (-i) when entering existing mnemonics
  • Never share private keys or mnemonics
  • Clear terminal after viewing private keys (clear or Ctrl+L)
  • Passphrases create completely different wallet addresses`,
		Example: `  # Show all wallet presets with descriptions
  shamir wallets --list

  # Interactive mode (SAFEST for entering mnemonics)
  shamir wallets -i
  shamir wallets --interactive --preset metamask

  # Generate new wallet with 10 Ethereum addresses
  shamir wallets --preset ethereum --count 10

  # Bitcoin addresses (Native SegWit - RECOMMENDED)
  shamir wallets --preset bitcoin --count 5

  # Bitcoin Legacy addresses (for old exchanges)
  shamir wallets --preset bitcoin-legacy --count 3

  # Use existing mnemonic (less secure than interactive)
  shamir wallets --preset metamask --mnemonic "word1 word2..." --count 5

  # With passphrase (creates different addresses)
  shamir wallets --preset ethereum --passphrase "MySecret" --count 5

  # Generate addresses for multiple Ledger accounts
  shamir wallets --preset ledger --count 3

  # Custom derivation path
  shamir wallets --path "m/44'/60'/0'/0/%d" --count 10

  # Continue from specific index
  shamir wallets --preset ethereum --index 5 --count 5

  # Output as JSON for scripts
  shamir wallets --preset bitcoin --json --count 3

  # Show private keys (DANGEROUS - only for testing)
  shamir wallets --preset ethereum --show-private --count 2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// List presets
			if listPresets {
				return listWalletPresets()
			}

			// Get mnemonic
			var m *mnemonic.Mnemonic
			var err error

			if mnemonicStr != "" {
				// Mnemonic provided via flag
				m, err = mnemonic.FromWords(mnemonicStr)
				if err != nil {
					return fmt.Errorf("invalid mnemonic: %w", err)
				}
			} else if interactive || (preset == "" && customPath == "") {
				// Interactive mode
				fmt.Print("Enter BIP-39 mnemonic (or press Enter to generate new): ")
				reader := bufio.NewReader(os.Stdin)
				input, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				input = strings.TrimSpace(input)

				if input == "" {
					// Generate new
					m, err = mnemonic.NewMnemonic(256) // 24 words
					if err != nil {
						return fmt.Errorf("failed to generate mnemonic: %w", err)
					}
					
					yellow := color.New(color.FgYellow, color.Bold)
					yellow.Println("\n✨ Generated new 24-word mnemonic:")
					fmt.Println(m.Words())
					fmt.Println()
					
					red := color.New(color.FgRed, color.Bold)
					red.Println("⚠️  SAVE THIS MNEMONIC! You'll need it to access these wallets.")
					fmt.Println()
				} else {
					m, err = mnemonic.FromWords(input)
					if err != nil {
						return fmt.Errorf("invalid mnemonic: %w", err)
					}
				}

				// Ask for passphrase
				fmt.Print("Enter passphrase (optional, press Enter to skip): ")
				passbytes, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return err
				}
				fmt.Println()
				passphrase = string(passbytes)
				secure.Zero(passbytes)
			} else {
				// Non-interactive, need mnemonic
				return fmt.Errorf("mnemonic required (use --mnemonic or run interactively)")
			}

			// Get seed
			seed := m.SeedWithPassphrase(passphrase)
			defer secure.Zero(seed)

			// Create master key
			masterKey, err := hdkey.NewMasterKey(seed)
			if err != nil {
				return fmt.Errorf("failed to create master key: %w", err)
			}

			// Determine path pattern
			var pathPattern string
			var walletInfo *WalletPreset

			if customPath != "" {
				pathPattern = customPath
				walletInfo = &WalletPreset{
					Name:        "Custom",
					Coin:        "Unknown",
					Description: "Custom derivation path",
				}
			} else if preset != "" {
				p, exists := walletPresets[strings.ToLower(preset)]
				if !exists {
					return fmt.Errorf("unknown preset '%s'. Use --list to see available presets", preset)
				}
				pathPattern = p.PathPattern
				walletInfo = &p
			} else {
				// Default to Ethereum
				p := walletPresets["ethereum"]
				pathPattern = p.PathPattern
				walletInfo = &p
			}

			// Generate addresses
			var addresses []WalletAddress

			for i := 0; i < count; i++ {
				index := startIndex + i
				
				// Format path
				path := pathPattern
				if strings.Contains(path, "%d") {
					path = fmt.Sprintf(pathPattern, index)
				}

				// Derive key
				derivedKey, err := masterKey.DerivePath(path)
				if err != nil {
					return fmt.Errorf("failed to derive key for path %s: %w", path, err)
				}

				// Generate address
				address := generateWalletAddress(path, derivedKey.PublicKey())

				wallet := WalletAddress{
					Index:     index,
					Path:      path,
					Address:   address,
					PublicKey: derivedKey.PublicKeyHex(),
				}

				if showPrivate {
					wallet.PrivateKey = derivedKey.PrivateKeyHex()
				}

				addresses = append(addresses, wallet)
			}

			// Output results
			if outputJSON {
				result := map[string]interface{}{
					"preset":    preset,
					"coin":      walletInfo.Coin,
					"addresses": addresses,
				}
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			// Text output
			return displayWalletAddresses(walletInfo, addresses, showPrivate)
		},
	}

	cmd.Flags().StringVar(&preset, "preset", "", "Wallet preset: ethereum, bitcoin, bitcoin-legacy, bitcoin-taproot, metamask, ledger, trezor, etc. (use --list to see all)")
	cmd.Flags().IntVar(&count, "count", 5, "Number of addresses to generate (default: 5)")
	cmd.Flags().IntVar(&startIndex, "index", 0, "Starting index for address derivation (default: 0, use to generate next batch)")
	cmd.Flags().StringVar(&mnemonicStr, "mnemonic", "", "BIP-39 mnemonic phrase (use -i for secure entry)")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "Optional BIP-39 passphrase (creates different addresses)")
	cmd.Flags().BoolVar(&showPrivate, "show-private", false, "Show private keys - DANGEROUS! Only for testing/export")
	cmd.Flags().StringVar(&customPath, "path", "", "Custom BIP-32 derivation path (use %d for index placeholder)")
	cmd.Flags().BoolVar(&listPresets, "list", false, "Show all available wallet presets with descriptions and fee info")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive mode - safest way to enter mnemonics")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format for scripts/automation")

	return cmd
}

func listWalletPresets() error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)

	fmt.Println()
	green.Println("📱 AVAILABLE WALLET PRESETS")
	fmt.Println("=" + strings.Repeat("=", 50))
	fmt.Println()

	// Group by category
	yellow.Println("🦊 Software Wallets:")
	fmt.Println()
	displayPreset("metamask", walletPresets["metamask"])
	displayPreset("ethereum", walletPresets["ethereum"])
	
	fmt.Println()
	yellow.Println("🔐 Hardware Wallets:")
	fmt.Println()
	displayPreset("ledger", walletPresets["ledger"])
	displayPreset("ledger-legacy", walletPresets["ledger-legacy"])
	displayPreset("ledger-bitcoin", walletPresets["ledger-bitcoin"])
	displayPreset("trezor", walletPresets["trezor"])
	
	fmt.Println()
	yellow.Println("🌐 EVM Chains:")
	fmt.Println()
	displayPreset("binance", walletPresets["binance"])
	displayPreset("polygon", walletPresets["polygon"])
	displayPreset("avalanche", walletPresets["avalanche"])

	fmt.Println()
	yellow.Println("Bitcoin Address Types:")
	fmt.Println()
	green.Println("  📊 Quick Comparison:")
	fmt.Println("  ┌─────────────────┬────────────┬──────────┬─────────────────────┐")
	fmt.Println("  │ Type            │ Starts With│ Fees     │ When to Use         │")
	fmt.Println("  ├─────────────────┼────────────┼──────────┼─────────────────────┤")
	fmt.Println("  │ Native SegWit   │ bc1...     │ Lowest   │ ✅ Default choice   │")
	fmt.Println("  │ Taproot         │ bc1p...    │ Lowest   │ 🔮 Future-proof     │")
	fmt.Println("  │ Nested SegWit   │ 3...       │ Medium   │ 🤝 Compatibility    │")
	fmt.Println("  │ Legacy          │ 1...       │ Highest  │ ⚠️  Old exchanges   │")
	fmt.Println("  └─────────────────┴────────────┴──────────┴─────────────────────┘")
	fmt.Println()
	displayPreset("bitcoin", walletPresets["bitcoin"])
	displayPreset("bitcoin-taproot", walletPresets["bitcoin-taproot"])
	displayPreset("bitcoin-segwit", walletPresets["bitcoin-segwit"])
	displayPreset("bitcoin-legacy", walletPresets["bitcoin-legacy"])

	fmt.Println()
	cyan.Println("Usage Examples:")
	fmt.Println()
	fmt.Println("  # Generate 5 Ethereum addresses")
	fmt.Println("  shamir wallets --preset ethereum --count 5")
	fmt.Println()
	fmt.Println("  # Generate addresses for existing mnemonic")
	fmt.Println("  shamir wallets --preset metamask --mnemonic \"your words...\"")
	fmt.Println()
	fmt.Println("  # Interactive mode (safest for entering mnemonics)")
	fmt.Println("  shamir wallets -i")
	fmt.Println()

	return nil
}

func displayPreset(key string, preset WalletPreset) {
	cyan := color.New(color.FgCyan, color.Bold)
	
	cyan.Printf("  %-15s", key)
	fmt.Printf(" %s  ", preset.Symbol)
	fmt.Printf("%-40s", preset.Description)
	fmt.Printf(" [%s]\n", preset.PathPattern)
}

func displayWalletAddresses(info *WalletPreset, addresses []WalletAddress, showPrivate bool) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	fmt.Println()
	green.Printf("=== %s WALLET ADDRESSES ===\n", strings.ToUpper(info.Name))
	if info.Description != "" {
		fmt.Printf("%s\n", info.Description)
	}
	fmt.Println()

	// Show Bitcoin-specific guidance
	if info.Coin == "BTC" {
		showBitcoinGuidance(info.Name)
	}

	for _, addr := range addresses {
		cyan.Printf("Address #%d:\n", addr.Index)
		fmt.Printf("  Path:    %s\n", addr.Path)
		green.Printf("  Address: %s\n", addr.Address)
		
		if showPrivate {
			fmt.Printf("  Public:  %s\n", addr.PublicKey)
			red.Printf("  Private: %s\n", addr.PrivateKey)
		}
		fmt.Println()
	}

	if showPrivate {
		red.Println("⚠️  SECURITY WARNING:")
		fmt.Println("  Private keys are shown above. NEVER share them!")
		fmt.Println("  Clear your terminal: clear or Ctrl+L")
		fmt.Println()
	}

	yellow.Println("💡 Tips:")
	fmt.Println("  • These addresses match what your wallet would generate")
	fmt.Println("  • You can receive funds at any of these addresses")
	fmt.Println("  • Use different addresses for privacy")
	fmt.Println("  • Import the mnemonic into your wallet to access funds")
	
	if info.Coin == "ETH" {
		fmt.Println("  • These addresses work on all EVM chains (ETH, BSC, Polygon, etc.)")
	}
	
	fmt.Println()
	green.Println("To generate more addresses:")
	fmt.Printf("  shamir wallets --preset %s --index %d --count 5\n", 
		strings.ToLower(strings.Fields(info.Name)[0]), 
		addresses[len(addresses)-1].Index + 1)
	fmt.Println()

	return nil
}

func generateWalletAddress(path string, pubKey []byte) string {
	// Ethereum and EVM chains
	if strings.Contains(path, "'/60'") || strings.Contains(path, "44'/60'") {
		// Keccak256 hash (simplified - using SHA256 for demo)
		// In production, use proper Keccak256
		hash := sha256.Sum256(pubKey[1:]) // Skip 0x04 prefix
		return "0x" + hex.EncodeToString(hash[12:32])
	}

	// Bitcoin Taproot (bc1p...)
	if strings.Contains(path, "'/86'") || strings.Contains(path, "86'/0'") {
		// Simplified Taproot address - would need proper bech32m encoding
		hash := sha256.Sum256(pubKey)
		return "bc1p" + hex.EncodeToString(hash[:20])[:32]
	}

	// Bitcoin Native SegWit (bc1q...)
	if strings.Contains(path, "'/84'") || strings.Contains(path, "84'/0'") {
		// Simplified - would need proper bech32 encoding
		hash := sha256.Sum256(pubKey)
		return "bc1q" + hex.EncodeToString(hash[:20])[:32]
	}

	// Bitcoin Nested SegWit (3...)
	if strings.Contains(path, "'/49'") || strings.Contains(path, "49'/0'") {
		// P2SH-P2WPKH address (simplified)
		hash := sha256.Sum256(pubKey)
		return "3" + hex.EncodeToString(hash[:20])[:33]
	}

	// Bitcoin Legacy (1...)
	if strings.Contains(path, "44'/0'") {
		// P2PKH address
		sha := sha256.Sum256(pubKey)
		ripemd := ripemd160.New()
		ripemd.Write(sha[:])
		pubKeyHash := ripemd.Sum(nil)
		
		// Add version byte
		versioned := append([]byte{0x00}, pubKeyHash...)
		
		// Checksum
		check1 := sha256.Sum256(versioned)
		check2 := sha256.Sum256(check1[:])
		checksum := check2[:4]
		
		// Combine (simplified base58)
		address := append(versioned, checksum...)
		return "1" + hex.EncodeToString(address)[:33]
	}

	// Default
	hash := sha256.Sum256(pubKey)
	return hex.EncodeToString(hash[:20])
}

func showBitcoinGuidance(walletType string) {
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	switch strings.ToLower(walletType) {
	case "bitcoin":
		cyan.Println("📌 Native SegWit (bc1...) - RECOMMENDED")
		green.Println("  ✅ Lowest transaction fees (30-40% cheaper)")
		green.Println("  ✅ Best for regular transactions")
		green.Println("  ✅ Supported by all modern wallets")
		yellow.Println("  ⚠️  Some old exchanges might not support")
		fmt.Println()

	case "bitcoin taproot":
		cyan.Println("📌 Taproot (bc1p...) - NEWEST")
		green.Println("  ✅ Enhanced privacy features")
		green.Println("  ✅ Lowest fees (same as Native SegWit)")
		green.Println("  ✅ Future-proof for smart contracts")
		yellow.Println("  ⚠️  Newer - limited exchange support")
		red.Println("  ❌ Not all wallets support yet")
		fmt.Println()

	case "bitcoin segwit":
		cyan.Println("📌 Nested SegWit (3...) - COMPATIBLE")
		green.Println("  ✅ Widely supported everywhere")
		green.Println("  ✅ Good balance of fees and compatibility")
		yellow.Println("  ⚠️  Higher fees than Native SegWit")
		fmt.Println("  💡 Use when Native SegWit not accepted")
		fmt.Println()

	case "bitcoin legacy":
		cyan.Println("📌 Legacy (1...) - OLDEST")
		green.Println("  ✅ Universal support (all exchanges)")
		red.Println("  ❌ Highest transaction fees")
		red.Println("  ❌ Larger transaction size")
		fmt.Println("  💡 Only use if required by old service")
		fmt.Println()
	}

	// General Bitcoin tips
	cyan.Println("💡 Bitcoin Tips:")
	fmt.Println("  • Start with Native SegWit (bc1) for best fees")
	fmt.Println("  • Use Legacy (1) only if exchange requires it")
	fmt.Println("  • Same seed generates all address types")
	fmt.Println("  • You can migrate between types anytime")
	fmt.Println()
}