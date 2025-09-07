package cli

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// NewExampleCommand creates an example/demo command
func NewExampleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "example [scenario]",
		Short: "Show practical examples and tutorials",
		Long: `Learn how to use Shamir secret sharing with practical examples
and step-by-step tutorials for common scenarios.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return showExampleMenu()
			}
			return showExample(args[0])
		},
	}

	return cmd
}

func showExampleMenu() error {
	green := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow)

	fmt.Println()
	green.Println("📚 SHAMIR SECRET SHARING EXAMPLES")
	fmt.Println("=" + strings.Repeat("=", 40))
	fmt.Println()

	cyan.Println("Available Examples:")
	fmt.Println()
	
	examples := []struct {
		cmd   string
		title string
		desc  string
	}{
		{"basic", "Basic 2-of-3 Sharing", "Simple secret splitting for personal use"},
		{"wallet", "Crypto Wallet Backup", "Secure BIP-39 mnemonic backup"},
		{"addresses", "Generate Wallet Addresses", "MetaMask, Ledger, and more"},
		{"family", "Family Estate Planning", "Multi-group sharing for inheritance"},
		{"company", "Company Secret Management", "Corporate key escrow system"},
		{"recovery", "Emergency Recovery", "Step-by-step recovery process"},
	}

	for _, ex := range examples {
		yellow.Printf("  shamir example %s\n", ex.cmd)
		fmt.Printf("    %s - %s\n\n", ex.title, ex.desc)
	}

	fmt.Println("Run any example to see detailed instructions and commands.")
	fmt.Println()

	return nil
}

func showExample(scenario string) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	fmt.Println()

	switch strings.ToLower(scenario) {
	case "basic":
		green.Println("📖 EXAMPLE: Basic 2-of-3 Secret Sharing")
		fmt.Println("=" + strings.Repeat("=", 40))
		fmt.Println()
		
		cyan.Println("Scenario:")
		fmt.Println("You have a password or secret you want to protect.")
		fmt.Println("You'll create 3 shares where any 2 can recover it.")
		fmt.Println()

		yellow.Println("Step 1: Split your secret")
		fmt.Println()
		fmt.Println("  shamir split --threshold 2 --shares 3")
		fmt.Println()
		fmt.Println("Or for a specific secret:")
		fmt.Println()
		fmt.Println("  shamir split -t 2 -n 3 --secret 4d7953656372657450617373776f7264")
		fmt.Println()

		yellow.Println("Step 2: Store shares separately")
		fmt.Println()
		fmt.Println("  Share 1 → Home safe")
		fmt.Println("  Share 2 → Bank deposit box")
		fmt.Println("  Share 3 → Trusted friend/family")
		fmt.Println()

		yellow.Println("Step 3: Recovery (need any 2 shares)")
		fmt.Println()
		fmt.Println("  shamir combine")
		fmt.Println()
		fmt.Println("Then enter any 2 of your 3 shares.")
		fmt.Println()

		green.Println("💡 Tips:")
		fmt.Println("- Add a passphrase for extra security: --passphrase")
		fmt.Println("- Save shares to file: --output shares.json")
		fmt.Println("- Test recovery before distributing shares!")

	case "wallet":
		green.Println("📖 EXAMPLE: Crypto Wallet Backup")
		fmt.Println("=" + strings.Repeat("=", 40))
		fmt.Println()
		
		cyan.Println("Scenario:")
		fmt.Println("You have a BIP-39 mnemonic (12-24 words) for your crypto wallet.")
		fmt.Println("You want to create a secure backup that's resistant to loss/theft.")
		fmt.Println()

		yellow.Println("Method 1: Interactive Backup Wizard")
		fmt.Println()
		fmt.Println("  shamir backup")
		fmt.Println()
		fmt.Println("Choose option 1 (BIP-39 mnemonic) and follow the prompts.")
		fmt.Println()

		yellow.Println("Method 2: Direct Commands")
		fmt.Println()
		fmt.Println("First, verify your mnemonic is valid:")
		fmt.Println()
		fmt.Println("  shamir verify \"your twelve word mnemonic phrase goes here\"")
		fmt.Println()
		fmt.Println("Create 3-of-5 shares with passphrase:")
		fmt.Println()
		fmt.Println("  shamir split -t 3 -n 5 -p \"strong-passphrase\"")
		fmt.Println()
		fmt.Println("Enter your mnemonic when prompted (hidden input).")
		fmt.Println()

		yellow.Println("Recommended Distribution:")
		fmt.Println()
		fmt.Println("  Share 1 → Personal safe")
		fmt.Println("  Share 2 → Bank deposit box")
		fmt.Println("  Share 3 → Parent/spouse")
		fmt.Println("  Share 4 → Sibling/friend")
		fmt.Println("  Share 5 → Attorney/executor")
		fmt.Println()
		fmt.Println("Any 3 people can recover, but no 2 can collude.")
		fmt.Println()

		red.Println("⚠️  Security Notes:")
		fmt.Println("- NEVER store shares digitally or online")
		fmt.Println("- Write shares on paper or engrave on metal")
		fmt.Println("- Test recovery with minimum shares first")
		fmt.Println("- Keep passphrase separate from shares")

	case "family":
		green.Println("📖 EXAMPLE: Family Estate Planning")
		fmt.Println("=" + strings.Repeat("=", 40))
		fmt.Println()
		
		cyan.Println("Scenario:")
		fmt.Println("You want family members to access important accounts/assets")
		fmt.Println("after you're gone, but no single person should have full control.")
		fmt.Println()

		yellow.Println("Setup: 2-of-3 Groups")
		fmt.Println()
		fmt.Println("Group 1: Spouse (needs 1 of 2 shares)")
		fmt.Println("Group 2: Children (needs 2 of 3 shares)")
		fmt.Println("Group 3: Attorney (needs 1 of 1 share)")
		fmt.Println()
		fmt.Println("Recovery requires shares from ANY 2 groups.")
		fmt.Println()

		yellow.Println("Command:")
		fmt.Println()
		fmt.Println("  shamir split \\")
		fmt.Println("    --group-threshold 2 \\")
		fmt.Println("    --groups \"1/2,2/3,1/1\" \\")
		fmt.Println("    --passphrase")
		fmt.Println()

		yellow.Println("Distribution Plan:")
		fmt.Println()
		fmt.Println("Spouse gets:")
		fmt.Println("  - Both Group 1 shares (in separate locations)")
		fmt.Println()
		fmt.Println("Each child gets:")
		fmt.Println("  - One Group 2 share")
		fmt.Println()
		fmt.Println("Attorney keeps:")
		fmt.Println("  - The Group 3 share")
		fmt.Println()

		cyan.Println("Recovery Scenarios:")
		fmt.Println()
		fmt.Println("✓ Spouse + Attorney")
		fmt.Println("✓ Spouse + Any 2 children")
		fmt.Println("✓ All 3 children + Attorney")
		fmt.Println("✗ Spouse alone (needs another group)")
		fmt.Println("✗ Children alone (need attorney or spouse)")
		fmt.Println()

		green.Println("💡 Benefits:")
		fmt.Println("- Prevents single point of failure")
		fmt.Println("- Requires collaboration for access")
		fmt.Println("- Flexible recovery options")
		fmt.Println("- Attorney ensures legal compliance")

	case "company":
		green.Println("📖 EXAMPLE: Company Secret Management")
		fmt.Println("=" + strings.Repeat("=", 40))
		fmt.Println()
		
		cyan.Println("Scenario:")
		fmt.Println("Your company needs to secure critical secrets (master keys,")
		fmt.Println("root passwords, recovery codes) with proper access control.")
		fmt.Println()

		yellow.Println("Recommended Setup:")
		fmt.Println()
		fmt.Println("3 groups, need 2 to recover:")
		fmt.Println("  - Executives: 2 of 3 shares")
		fmt.Println("  - IT/Security: 2 of 4 shares")
		fmt.Println("  - Board/External: 1 of 2 shares")
		fmt.Println()

		yellow.Println("Command:")
		fmt.Println()
		fmt.Println("  shamir split \\")
		fmt.Println("    --group-threshold 2 \\")
		fmt.Println("    --groups \"2/3,2/4,1/2\" \\")
		fmt.Println("    --output company-recovery.json")
		fmt.Println()

		yellow.Println("Distribution:")
		fmt.Println()
		fmt.Println("Executives:")
		fmt.Println("  - CEO: Share 1-1")
		fmt.Println("  - CTO: Share 1-2")
		fmt.Println("  - CFO: Share 1-3")
		fmt.Println()
		fmt.Println("IT/Security Team:")
		fmt.Println("  - Security Lead: Share 2-1")
		fmt.Println("  - Senior Admin 1: Share 2-2")
		fmt.Println("  - Senior Admin 2: Share 2-3")
		fmt.Println("  - Backup Admin: Share 2-4")
		fmt.Println()
		fmt.Println("External:")
		fmt.Println("  - Board Member: Share 3-1")
		fmt.Println("  - Legal/Auditor: Share 3-2")
		fmt.Println()

		cyan.Println("Access Control Matrix:")
		fmt.Println()
		fmt.Println("✓ 2 Executives + Security Lead")
		fmt.Println("✓ 2 IT Admins + Board Member")
		fmt.Println("✓ CEO + CTO + Legal")
		fmt.Println("✗ All IT team (need executive/board)")
		fmt.Println("✗ All executives (need IT/board)")
		fmt.Println()

		green.Println("💡 Best Practices:")
		fmt.Println("- Document the process in your DR plan")
		fmt.Println("- Test recovery quarterly")
		fmt.Println("- Rotate shares when people leave")
		fmt.Println("- Use hardware security modules if available")
		fmt.Println("- Consider geographic distribution")

	case "addresses":
		green.Println("📖 EXAMPLE: Generate Wallet Addresses")
		fmt.Println("=" + strings.Repeat("=", 40))
		fmt.Println()
		
		cyan.Println("Scenario:")
		fmt.Println("You need to generate the same addresses your hardware wallet")
		fmt.Println("or MetaMask would generate from your mnemonic.")
		fmt.Println()

		yellow.Println("Step 1: View Available Wallet Presets")
		fmt.Println()
		fmt.Println("  shamir wallets --list")
		fmt.Println()
		
		yellow.Println("Step 2: Generate Addresses for Your Wallet Type")
		fmt.Println()
		fmt.Println("MetaMask/Ethereum:")
		fmt.Println("  shamir wallets --preset metamask --count 5")
		fmt.Println()
		fmt.Println("Ledger Live (multiple accounts):")
		fmt.Println("  shamir wallets --preset ledger-live --count 3")
		fmt.Println()
		fmt.Println("Bitcoin (modern bc1 addresses):")
		fmt.Println("  shamir wallets --preset bitcoin --count 5")
		fmt.Println()

		yellow.Println("Step 3: Use with Existing Mnemonic")
		fmt.Println()
		fmt.Println("From command line (less secure):")
		fmt.Println("  shamir wallets --preset ethereum \\")
		fmt.Println("    --mnemonic \"word1 word2 ... word12\" \\")
		fmt.Println("    --count 10")
		fmt.Println()
		fmt.Println("Interactive mode (more secure):")
		fmt.Println("  shamir wallets -i --preset ethereum")
		fmt.Println()

		yellow.Println("Step 4: With Passphrase (Advanced)")
		fmt.Println()
		fmt.Println("Some wallets use an additional passphrase:")
		fmt.Println("  shamir wallets --preset trezor \\")
		fmt.Println("    --mnemonic \"your words\" \\")
		fmt.Println("    --passphrase \"your passphrase\" \\")
		fmt.Println("    --count 5")
		fmt.Println()

		cyan.Println("Common Wallet Paths:")
		fmt.Println()
		fmt.Println("  MetaMask/ETH:     m/44'/60'/0'/0/0")
		fmt.Println("  Ledger Live ETH:  m/44'/60'/0'/0/0  (account 0)")
		fmt.Println("                    m/44'/60'/1'/0/0  (account 1)")
		fmt.Println()
		red.Println("  📊 Bitcoin Address Types & Fees:")
		fmt.Println("  Bitcoin Legacy:   m/44'/0'/0'/0/0   (1... addresses)    💰 HIGH fees")
		fmt.Println("  Bitcoin SegWit:   m/49'/0'/0'/0/0   (3... addresses)    💰 Medium fees")
		fmt.Println("  Bitcoin Native:   m/84'/0'/0'/0/0   (bc1q... addresses) 💰 LOW fees ✅")
		fmt.Println("  Bitcoin Taproot:  m/86'/0'/0'/0/0   (bc1p... addresses) 💰 LOW fees 🔮")
		fmt.Println()
		
		yellow.Println("  🏆 Bitcoin Recommendations:")
		fmt.Println("  • Default choice: Native SegWit (bc1q...)")
		fmt.Println("    shamir wallets --preset bitcoin")
		fmt.Println()
		fmt.Println("  • For old exchanges: Legacy (1...)")
		fmt.Println("    shamir wallets --preset bitcoin-legacy")
		fmt.Println()
		fmt.Println("  • Future-proof: Taproot (bc1p...)")
		fmt.Println("    shamir wallets --preset bitcoin-taproot")
		fmt.Println()

		green.Println("💡 Pro Tips:")
		fmt.Println("- Addresses generated match exactly what your wallet shows")
		fmt.Println("- Use different addresses for each transaction (privacy)")
		fmt.Println("- The extended public key can generate all child addresses")
		fmt.Println("- Never share your mnemonic or private keys")
		fmt.Println("- Passphrases create completely different wallets")

	case "recovery":
		green.Println("📖 EXAMPLE: Emergency Recovery Process")
		fmt.Println("=" + strings.Repeat("=", 40))
		fmt.Println()
		
		cyan.Println("Step-by-Step Recovery Guide:")
		fmt.Println()

		yellow.Println("Step 1: Gather Shares")
		fmt.Println()
		fmt.Println("Collect the minimum required shares from their locations.")
		fmt.Println("For 2-of-3, you need any 2 shares.")
		fmt.Println()

		yellow.Println("Step 2: Check Compatibility")
		fmt.Println()
		fmt.Println("Verify shares are from the same secret:")
		fmt.Println()
		fmt.Println("  shamir check")
		fmt.Println()
		fmt.Println("Enter your shares when prompted.")
		fmt.Println("The tool will tell you if recovery is possible.")
		fmt.Println()

		yellow.Println("Step 3: Recover Secret")
		fmt.Println()
		fmt.Println("Method A - Interactive:")
		fmt.Println()
		fmt.Println("  shamir restore")
		fmt.Println()
		fmt.Println("Method B - Direct:")
		fmt.Println()
		fmt.Println("  shamir combine")
		fmt.Println()
		fmt.Println("Enter shares and passphrase (if used).")
		fmt.Println()

		yellow.Println("Step 4: Verify Recovery")
		fmt.Println()
		fmt.Println("For hex output:")
		fmt.Println()
		fmt.Println("  shamir combine --hex")
		fmt.Println()
		fmt.Println("For BIP-39 mnemonics, the recovered secret")
		fmt.Println("is the seed, not the original words.")
		fmt.Println()

		red.Println("⚠️  Troubleshooting:")
		fmt.Println()
		fmt.Println("❌ \"Insufficient shares\"")
		fmt.Println("   → Need more shares for threshold")
		fmt.Println()
		fmt.Println("❌ \"Identifier mismatch\"")
		fmt.Println("   → Shares from different secrets")
		fmt.Println()
		fmt.Println("❌ \"Invalid checksum\"")
		fmt.Println("   → Share corrupted or modified")
		fmt.Println()
		fmt.Println("❌ Wrong recovery result")
		fmt.Println("   → Check passphrase is correct")
		fmt.Println()

		green.Println("💡 Recovery Tips:")
		fmt.Println("- Work in a secure, private location")
		fmt.Println("- Use an air-gapped computer if possible")
		fmt.Println("- Clear clipboard and terminal after")
		fmt.Println("- Re-split with new shares after recovery")

	default:
		return fmt.Errorf("unknown example: %s", scenario)
	}

	fmt.Println()
	cyan.Println("Learn more:")
	fmt.Println("  shamir example            (show all examples)")
	fmt.Println("  shamir <command> --help   (detailed help)")
	fmt.Println()

	return nil
}