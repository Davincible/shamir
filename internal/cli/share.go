package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Davincible/shamir/pkg/crypto/pvss"
	"github.com/Davincible/shamir/pkg/crypto/secretsharing"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ShareCommand represents the unified secret sharing command
type ShareCommand struct {
	scheme          string
	threshold       int
	shares          int
	groups          string
	groupThreshold  int
	passphrase      string
	output          string
	input           string
	interactive     bool
	verify          bool
	mnemonic        bool
	advanced        bool
}

// NewShareCommand creates the unified share command
func NewShareCommand() *cobra.Command {
	sc := &ShareCommand{}
	
	cmd := &cobra.Command{
		Use:   "share",
		Short: "Unified secret sharing with multiple schemes",
		Long: `Advanced secret sharing supporting multiple cryptographic schemes.

This command provides a unified interface for:
- SLIP-0039: Shamir's Secret Sharing with mnemonic encoding (default)
- PVSS: Publicly Verifiable Secret Sharing with cryptographic proofs

Features:
- Interactive mode for easy setup
- Support for hierarchical sharing (SLIP-0039)
- Public verifiability (PVSS)
- Mnemonic encoding for both schemes
- Advanced configuration options`,
		Example: `  # Interactive mode (recommended)
  shamir share -i
  
  # Quick 2-of-3 sharing with SLIP-0039
  shamir share --split -t 2 -n 3
  
  # PVSS with public verification
  shamir share --split --scheme pvss -t 3 -n 5
  
  # Combine shares
  shamir share --combine -i shares.json
  
  # Advanced hierarchical sharing
  shamir share --split --advanced --groups "2/3,3/5" --group-threshold 2`,
		RunE: sc.run,
	}
	
	// Operation mode flags
	cmd.Flags().BoolP("split", "s", false, "Split a secret into shares")
	cmd.Flags().BoolP("combine", "c", false, "Combine shares to recover secret")
	cmd.Flags().Bool("verify", false, "Verify share validity")
	
	// Scheme selection
	cmd.Flags().StringVar(&sc.scheme, "scheme", "slip039", "Secret sharing scheme (slip039, pvss)")
	
	// Basic configuration
	cmd.Flags().IntVarP(&sc.threshold, "threshold", "t", 0, "Minimum shares needed for recovery")
	cmd.Flags().IntVarP(&sc.shares, "shares", "n", 0, "Total number of shares to create")
	
	// Advanced configuration
	cmd.Flags().StringVar(&sc.groups, "groups", "", "Group configuration (e.g., '2/3,3/5')")
	cmd.Flags().IntVar(&sc.groupThreshold, "group-threshold", 0, "Number of groups required")
	cmd.Flags().BoolVar(&sc.advanced, "advanced", false, "Enable advanced configuration mode")
	
	// Security options
	cmd.Flags().StringVarP(&sc.passphrase, "passphrase", "p", "", "Optional passphrase for encryption")
	
	// I/O options
	cmd.Flags().StringVarP(&sc.output, "output", "o", "", "Output file for shares")
	cmd.Flags().StringVarP(&sc.input, "input", "i", "", "Input file for shares")
	
	// UX options
	cmd.Flags().BoolVar(&sc.interactive, "interactive", false, "Interactive mode")
	cmd.Flags().BoolVar(&sc.mnemonic, "mnemonic", true, "Use mnemonic encoding (when available)")
	
	return cmd
}

func (sc *ShareCommand) run(cmd *cobra.Command, args []string) error {
	// Determine operation mode
	split, _ := cmd.Flags().GetBool("split")
	combine, _ := cmd.Flags().GetBool("combine")
	verify, _ := cmd.Flags().GetBool("verify")
	
	// Interactive mode takes precedence
	if sc.interactive || (!split && !combine && !verify) {
		return sc.runInteractive()
	}
	
	// Execute based on mode
	switch {
	case split:
		return sc.runSplit()
	case combine:
		return sc.runCombine()
	case verify:
		return sc.runVerify()
	default:
		return fmt.Errorf("please specify an operation: --split, --combine, or --verify")
	}
}

func (sc *ShareCommand) runInteractive() error {
	reader := bufio.NewReader(os.Stdin)
	
	// Welcome message
	color.Cyan("\n🔐 Advanced Secret Sharing Tool\n")
	fmt.Println("This tool helps you securely split and combine secrets using advanced cryptographic schemes.\n")
	
	// Choose operation
	fmt.Println("What would you like to do?")
	fmt.Println("1) Split a secret into shares")
	fmt.Println("2) Combine shares to recover a secret")
	fmt.Println("3) Verify share validity")
	fmt.Println("4) Learn about secret sharing schemes")
	
	fmt.Print("\nChoice (1-4): ")
	choice, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	choice = strings.TrimSpace(choice)
	
	switch choice {
	case "1":
		return sc.interactiveSplit(reader)
	case "2":
		return sc.interactiveCombine(reader)
	case "3":
		return sc.interactiveVerify(reader)
	case "4":
		return sc.showEducationalInfo()
	default:
		return fmt.Errorf("invalid choice")
	}
}

func (sc *ShareCommand) interactiveSplit(reader *bufio.Reader) error {
	// Choose scheme
	fmt.Println("\n📊 Select Secret Sharing Scheme:")
	fmt.Println("\n1) SLIP-0039 (Recommended)")
	fmt.Println("   ✓ Hardware wallet compatible")
	fmt.Println("   ✓ Mnemonic encoding")
	fmt.Println("   ✓ Hierarchical sharing")
	fmt.Println("   ✓ Passphrase protection")
	
	fmt.Println("\n2) PVSS (Advanced)")
	fmt.Println("   ✓ Publicly verifiable")
	fmt.Println("   ✓ Cryptographic proofs")
	fmt.Println("   ✓ No trust required")
	fmt.Println("   ✓ Mnemonic encoding (new!)")
	
	fmt.Print("\nChoice (1-2) [1]: ")
	schemeChoice, _ := reader.ReadString('\n')
	schemeChoice = strings.TrimSpace(schemeChoice)
	
	if schemeChoice == "2" {
		sc.scheme = "pvss"
	} else {
		sc.scheme = "slip039"
	}
	
	// Get secret
	fmt.Println("\n🔑 Enter your secret:")
	fmt.Println("1) Enter text secret")
	fmt.Println("2) Enter hex-encoded secret")
	fmt.Println("3) Generate random secret")
	fmt.Println("4) Enter BIP-39 mnemonic")
	
	fmt.Print("\nChoice (1-4): ")
	secretChoice, _ := reader.ReadString('\n')
	secretChoice = strings.TrimSpace(secretChoice)
	
	var secret []byte
	var err error
	
	switch secretChoice {
	case "1":
		fmt.Print("Enter secret text: ")
		if term.IsTerminal(int(os.Stdin.Fd())) {
			secret, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
		} else {
			text, _ := reader.ReadString('\n')
			secret = []byte(strings.TrimSpace(text))
		}
		
	case "2":
		fmt.Print("Enter hex-encoded secret: ")
		hexStr, _ := reader.ReadString('\n')
		hexStr = strings.TrimSpace(hexStr)
		secret, err = hex.DecodeString(hexStr)
		
	case "3":
		fmt.Print("Secret length (16 or 32 bytes) [32]: ")
		lenStr, _ := reader.ReadString('\n')
		lenStr = strings.TrimSpace(lenStr)
		if lenStr == "" {
			lenStr = "32"
		}
		length, _ := strconv.Atoi(lenStr)
		secret = generateRandomSecret(length)
		color.Green("✓ Generated %d-byte random secret", length)
		
	case "4":
		// Handle BIP-39 mnemonic input
		fmt.Println("Enter BIP-39 mnemonic (12-24 words):")
		mnemonic, _ := reader.ReadString('\n')
		mnemonic = strings.TrimSpace(mnemonic)
		secret, err = mnemonicToSecret(mnemonic)
	}
	
	if err != nil {
		return fmt.Errorf("failed to process secret: %w", err)
	}
	
	// Configure sharing parameters
	if sc.scheme == "slip039" && sc.advanced {
		return sc.configureSLIP039Advanced(reader, secret)
	}
	
	// Simple configuration
	fmt.Print("\nMinimum shares needed for recovery (threshold) [2]: ")
	thresholdStr, _ := reader.ReadString('\n')
	thresholdStr = strings.TrimSpace(thresholdStr)
	if thresholdStr == "" {
		sc.threshold = 2
	} else {
		sc.threshold, _ = strconv.Atoi(thresholdStr)
	}
	
	fmt.Print("Total number of shares to create [3]: ")
	sharesStr, _ := reader.ReadString('\n')
	sharesStr = strings.TrimSpace(sharesStr)
	if sharesStr == "" {
		sc.shares = 3
	} else {
		sc.shares, _ = strconv.Atoi(sharesStr)
	}
	
	// Optional passphrase
	fmt.Print("\nAdd passphrase protection? (y/N): ")
	passphraseChoice, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(passphraseChoice)) == "y" {
		fmt.Print("Enter passphrase: ")
		passphraseBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
		sc.passphrase = string(passphraseBytes)
		fmt.Println()
		
		fmt.Print("Confirm passphrase: ")
		confirmBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		
		if string(confirmBytes) != sc.passphrase {
			return fmt.Errorf("passphrases do not match")
		}
	}
	
	// Perform the split
	shares, err := sc.performSplit(secret)
	if err != nil {
		return err
	}
	
	// Display results
	return sc.displayShares(shares)
}

func (sc *ShareCommand) performSplit(secret []byte) ([]secretsharing.Share, error) {
	config := secretsharing.SecretSharingConfig{
		Scheme:         secretsharing.SchemeType(sc.scheme),
		GroupThreshold: 1,
		Groups: []secretsharing.GroupConfiguration{
			{
				MemberThreshold: sc.threshold,
				MemberCount:     sc.shares,
			},
		},
		Passphrase: sc.passphrase,
	}
	
	// Handle advanced group configuration
	if sc.groups != "" {
		groups, groupThreshold, err := parseGroupConfig(sc.groups, sc.groupThreshold)
		if err != nil {
			return nil, err
		}
		config.Groups = groups
		config.GroupThreshold = groupThreshold
	}
	
	// Get the appropriate sharer
	sharer, err := secretsharing.DefaultRegistry.Get(config.Scheme)
	if err != nil {
		return nil, err
	}
	
	// Validate configuration
	if err := sharer.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Split the secret
	shares, err := sharer.Split(secret, config)
	if err != nil {
		return nil, fmt.Errorf("failed to split secret: %w", err)
	}
	
	// If PVSS and mnemonic encoding requested, encode shares
	if sc.scheme == "pvss" && sc.mnemonic {
		return sc.encodePVSSMnemonics(shares)
	}
	
	return shares, nil
}

func (sc *ShareCommand) encodePVSSMnemonics(shares []secretsharing.Share) ([]secretsharing.Share, error) {
	// Create a PVSS system to use mnemonic encoding
	pvssSystem, err := pvss.NewPVSSSystem(pvss.CurveP256, sc.threshold, sc.shares)
	if err != nil {
		return nil, err
	}
	
	encodedShares := make([]secretsharing.Share, len(shares))
	
	for i, share := range shares {
		// Deserialize PVSS share
		var pvssShare pvss.PVSSShare
		if err := json.Unmarshal(share.Data, &pvssShare); err != nil {
			return nil, fmt.Errorf("failed to deserialize PVSS share: %w", err)
		}
		
		// Encode as mnemonic
		mnemonicShare, err := pvssSystem.EncodeMnemonic(&pvssShare)
		if err != nil {
			return nil, fmt.Errorf("failed to encode share %d as mnemonic: %w", i+1, err)
		}
		
		// Update share with mnemonic
		encodedShares[i] = share
		encodedShares[i].Mnemonic = mnemonicShare.Mnemonic
	}
	
	return encodedShares, nil
}

func (sc *ShareCommand) displayShares(shares []secretsharing.Share) error {
	color.Green("\n✅ Secret successfully split into %d shares!\n", len(shares))
	
	if sc.threshold > 1 {
		color.Yellow("⚠️  You need at least %d shares to recover the secret.\n", sc.threshold)
	}
	
	// Save to file if requested
	if sc.output != "" {
		if err := sc.saveShares(shares); err != nil {
			return fmt.Errorf("failed to save shares: %w", err)
		}
		color.Green("✓ Shares saved to %s\n", sc.output)
	}
	
	// Display shares
	for i, share := range shares {
		fmt.Printf("\n" + strings.Repeat("=", 70) + "\n")
		
		if sc.scheme == "pvss" {
			color.Cyan("PVSS Share #%d (Publicly Verifiable)\n", share.Info.MemberIndex)
		} else {
			color.Cyan("Share #%d (Group %d, Member %d)\n",
				i+1, share.Info.GroupIndex, share.Info.MemberIndex)
		}
		
		fmt.Printf("Identifier: %s\n", share.Info.Identifier)
		fmt.Printf("Threshold: %d of %d\n",
			share.Info.MemberThreshold, len(shares))
		
		if share.Mnemonic != "" {
			fmt.Println("\nMnemonic:")
			// Format mnemonic nicely
			words := strings.Split(share.Mnemonic, " ")
			for j := 0; j < len(words); j += 4 {
				end := j + 4
				if end > len(words) {
					end = len(words)
				}
				fmt.Printf("  %s\n", strings.Join(words[j:end], " "))
			}
		} else if len(share.Data) > 0 {
			fmt.Printf("\nData (hex): %s\n", hex.EncodeToString(share.Data))
		}
		
		if share.Info.IsVerifiable {
			color.Green("✓ This share is publicly verifiable")
		}
	}
	
	fmt.Printf("\n" + strings.Repeat("=", 70) + "\n")
	
	// Security reminders
	color.Yellow("\n🔒 Security Reminders:")
	fmt.Println("• Store each share in a different secure location")
	fmt.Println("• Never store shares digitally unless encrypted")
	fmt.Println("• Test recovery with a subset of shares before distributing")
	fmt.Println("• Keep your passphrase secure if you used one")
	
	return nil
}

func (sc *ShareCommand) saveShares(shares []secretsharing.Share) error {
	// Create output structure
	output := struct {
		Scheme    string                   `json:"scheme"`
		Timestamp string                   `json:"timestamp"`
		Threshold int                      `json:"threshold"`
		Total     int                      `json:"total"`
		Shares    []secretsharing.Share    `json:"shares"`
	}{
		Scheme:    sc.scheme,
		Timestamp: fmt.Sprintf("%d", time.Now().Unix()),
		Threshold: sc.threshold,
		Total:     len(shares),
		Shares:    shares,
	}
	
	// Marshal to JSON
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	
	// Write to file
	return os.WriteFile(sc.output, data, 0600)
}

func (sc *ShareCommand) runSplit() error {
	// Implementation for non-interactive split
	// This would be similar to interactiveSplit but without prompts
	return fmt.Errorf("non-interactive split not yet implemented")
}

func (sc *ShareCommand) runCombine() error {
	// Implementation for combining shares
	return fmt.Errorf("combine not yet implemented")
}

func (sc *ShareCommand) runVerify() error {
	// Implementation for verifying shares
	return fmt.Errorf("verify not yet implemented")
}

func (sc *ShareCommand) interactiveCombine(reader *bufio.Reader) error {
	// Implementation for interactive combine
	return fmt.Errorf("interactive combine not yet implemented")
}

func (sc *ShareCommand) interactiveVerify(reader *bufio.Reader) error {
	// Implementation for interactive verify
	return fmt.Errorf("interactive verify not yet implemented")
}

func (sc *ShareCommand) configureSLIP039Advanced(reader *bufio.Reader, secret []byte) error {
	// Implementation for advanced SLIP-0039 configuration
	return fmt.Errorf("advanced configuration not yet implemented")
}

func (sc *ShareCommand) showEducationalInfo() error {
	color.Cyan("\n📚 Secret Sharing Schemes Explained\n")
	
	fmt.Println("=" + strings.Repeat("=", 69))
	color.Yellow("\nSLIP-0039 (Shamir's Secret Sharing)")
	fmt.Println(strings.Repeat("-", 70))
	
	fmt.Println(`
SLIP-0039 is a standard for splitting secrets using Shamir's Secret 
Sharing algorithm. It was developed by SatoshiLabs for Trezor wallets.

Key Features:
• Threshold-based recovery (e.g., need 3 of 5 shares)
• Mnemonic encoding using words (human-readable)
• Hierarchical sharing with groups
• Passphrase protection for plausible deniability
• Hardware wallet compatibility

Best For:
• Cryptocurrency wallet backups
• Password manager master keys
• Estate planning and inheritance
• Corporate secret management

Security:
• Information-theoretically secure
• No single share reveals information
• Resistant to brute force attacks`)
	
	fmt.Println("\n" + strings.Repeat("=", 70))
	color.Yellow("\nPVSS (Publicly Verifiable Secret Sharing)")
	fmt.Println(strings.Repeat("-", 70))
	
	fmt.Println(`
PVSS uses elliptic curve cryptography to create shares that can be
verified by anyone without revealing the secret.

Key Features:
• Public verifiability of share authenticity
• Cryptographic proofs of correctness
• No need to trust the dealer
• Commitment schemes for integrity
• Now with mnemonic encoding support!

Best For:
• Distributed systems and protocols
• Trustless environments
• Public auditing requirements
• Blockchain applications

Security:
• Computationally secure (elliptic curves)
• Publicly verifiable commitments
• Resistant to malicious dealers`)
	
	fmt.Println("\n" + strings.Repeat("=", 70))
	
	color.Green("\n💡 Quick Comparison:")
	fmt.Println(`
┌─────────────┬──────────────────┬──────────────────┐
│ Feature     │ SLIP-0039        │ PVSS             │
├─────────────┼──────────────────┼──────────────────┤
│ Verifiable  │ After combining  │ Before combining │
│ Hierarchical│ ✓                │ ✗ (single-level) │
│ Mnemonic    │ ✓                │ ✓ (new!)         │
│ HW Wallet   │ ✓                │ ✗                │
│ Trust Model │ Trust dealer     │ Trustless        │
└─────────────┴──────────────────┴──────────────────┘`)
	
	fmt.Println("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadString('\n')
	
	return nil
}

// Helper functions

func generateRandomSecret(length int) []byte {
	secret := make([]byte, length)
	if _, err := rand.Read(secret); err != nil {
		panic(fmt.Sprintf("failed to generate random secret: %v", err))
	}
	return secret
}

func mnemonicToSecret(mnemonic string) ([]byte, error) {
	// Implementation to convert BIP-39 mnemonic to secret
	// This would validate and convert the mnemonic to entropy
	return nil, fmt.Errorf("mnemonic conversion not yet implemented")
}

func parseGroupConfig(groupStr string, groupThreshold int) ([]secretsharing.GroupConfiguration, int, error) {
	// Parse group configuration string like "2/3,3/5"
	// Returns group configurations and group threshold
	return nil, 0, fmt.Errorf("group parsing not yet implemented")
}