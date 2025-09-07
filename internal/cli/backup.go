package cli

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/crypto/slip039"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// NewBackupCommand creates an interactive backup wizard
func NewBackupCommand() *cobra.Command {
	var (
		outputDir string
		testMode  bool
	)

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Interactive wizard to backup a secret or mnemonic",
		Long: `An interactive wizard that guides you through backing up your secret
using SLIP-0039 Shamir's Secret Sharing. Perfect for cryptocurrency
wallets, passwords, or any sensitive data.`,
		Example: `  # Start interactive backup wizard
  shamir backup

  # Save shares to specific directory
  shamir backup --output ~/backups

  # Test mode (for learning)
  shamir backup --test`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBackupWizard(outputDir, testMode)
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Directory to save share files")
	cmd.Flags().BoolVar(&testMode, "test", false, "Test mode with example data")

	return cmd
}

func runBackupWizard(outputDir string, testMode bool) error {
	reader := bufio.NewReader(os.Stdin)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)
	red := color.New(color.FgRed, color.Bold)

	// Welcome message
	fmt.Println()
	green.Println("🔐 SHAMIR SECRET BACKUP WIZARD")
	fmt.Println("=" + strings.Repeat("=", 40))
	fmt.Println()
	
	if testMode {
		yellow.Println("⚠️  TEST MODE - Using example data")
		fmt.Println()
	}

	// Step 1: Choose what to backup
	cyan.Println("Step 1: What would you like to backup?")
	fmt.Println()
	fmt.Println("  1) BIP-39 mnemonic phrase (12-24 words)")
	fmt.Println("  2) Raw secret (password, API key, etc.)")
	fmt.Println("  3) Generate new random secret")
	fmt.Println()
	fmt.Print("Choose [1-3]: ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var masterSecret []byte
	var sourceType string

	switch choice {
	case "1":
		sourceType = "mnemonic"
		if testMode {
			// Use test mnemonic
			fmt.Println()
			yellow.Println("Using test mnemonic (DO NOT USE FOR REAL FUNDS):")
			testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
			fmt.Println(testMnemonic)
			m, _ := mnemonic.FromWords(testMnemonic)
			masterSecret = m.Seed()
		} else {
			fmt.Println()
			fmt.Println("Enter your BIP-39 mnemonic phrase:")
			fmt.Print("> ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			
			m, err := mnemonic.FromWords(input)
			if err != nil {
				red.Printf("❌ Invalid mnemonic: %v\n", err)
				return err
			}
			masterSecret = m.Seed()
			green.Println("✓ Valid mnemonic")
		}

	case "2":
		sourceType = "secret"
		if testMode {
			masterSecret = []byte("test-secret-for-demonstration-32")
			fmt.Println()
			yellow.Println("Using test secret:", string(masterSecret))
		} else {
			fmt.Println()
			fmt.Println("Enter your secret (or hex-encoded):")
			secret, err := readSecretInteractive()
			if err != nil {
				return err
			}
			masterSecret = secret
		}

	case "3":
		sourceType = "generated"
		fmt.Println()
		fmt.Println("Choose secret size:")
		fmt.Println("  1) 128-bit (16 bytes) - Good for most uses")
		fmt.Println("  2) 256-bit (32 bytes) - Maximum security")
		fmt.Print("Choose [1-2]: ")
		
		sizeChoice, _ := reader.ReadString('\n')
		sizeChoice = strings.TrimSpace(sizeChoice)
		
		size := 16
		if sizeChoice == "2" {
			size = 32
		}
		
		generated, err := slip039.GenerateMasterSecret(size)
		if err != nil {
			return err
		}
		masterSecret = generated
		
		fmt.Println()
		green.Println("✓ Generated new secret:")
		fmt.Printf("Hex: %s\n", hex.EncodeToString(masterSecret))

	default:
		return fmt.Errorf("invalid choice")
	}

	// Step 2: Choose sharing configuration
	fmt.Println()
	cyan.Println("Step 2: How should the secret be split?")
	fmt.Println()
	fmt.Println("  1) Simple (e.g., 2 of 3 shares)")
	fmt.Println("  2) Distributed (e.g., family + bank + lawyer)")
	fmt.Println("  3) Advanced (custom groups)")
	fmt.Println()
	fmt.Print("Choose [1-3]: ")

	configChoice, _ := reader.ReadString('\n')
	configChoice = strings.TrimSpace(configChoice)

	var groups []slip039.GroupConfiguration
	var groupThreshold byte
	var description string

	switch configChoice {
	case "1":
		fmt.Println()
		fmt.Print("How many shares total? [3-16]: ")
		totalStr, _ := reader.ReadString('\n')
		total := parseInt(strings.TrimSpace(totalStr), 3)

		fmt.Print("How many needed to recover? [2-" + fmt.Sprint(total) + "]: ")
		thresholdStr, _ := reader.ReadString('\n')
		threshold := parseInt(strings.TrimSpace(thresholdStr), 2)

		groups = slip039.SimpleConfiguration(byte(threshold), byte(total))
		groupThreshold = 1
		description = fmt.Sprintf("%d of %d shares", threshold, total)

	case "2":
		fmt.Println()
		yellow.Println("Distributed Backup (Recommended)")
		fmt.Println("Creates 3 groups: Personal, Trusted, Emergency")
		fmt.Println("Need shares from 2 groups to recover")
		fmt.Println()
		
		groups = []slip039.GroupConfiguration{
			{MemberThreshold: 1, MemberCount: 2}, // Personal (1 of 2)
			{MemberThreshold: 2, MemberCount: 3}, // Trusted (2 of 3)
			{MemberThreshold: 1, MemberCount: 1}, // Emergency (1 of 1)
		}
		groupThreshold = 2
		description = "Distributed (2 of 3 groups)"

	default:
		// Advanced - use simple for now
		groups = slip039.SimpleConfiguration(2, 3)
		groupThreshold = 1
		description = "2 of 3 shares"
	}

	// Step 3: Passphrase
	fmt.Println()
	cyan.Println("Step 3: Add passphrase protection?")
	fmt.Println()
	fmt.Println("A passphrase adds an extra layer of security.")
	fmt.Println("Even if someone finds enough shares, they still need the passphrase.")
	fmt.Println()
	fmt.Print("Use passphrase? [y/N]: ")

	passphraseChoice, _ := reader.ReadString('\n')
	passphraseChoice = strings.TrimSpace(strings.ToLower(passphraseChoice))

	var passphrase string
	if passphraseChoice == "y" || passphraseChoice == "yes" {
		if testMode {
			passphrase = "test-passphrase"
			yellow.Println("Using test passphrase:", passphrase)
		} else {
			pass, err := readPasswordWithStars("Enter passphrase: ")
			if err != nil {
				return err
			}
			pass2, err := readPasswordWithStars("Confirm passphrase: ")
			if err != nil {
				return err
			}
			if pass != pass2 {
				return fmt.Errorf("passphrases don't match")
			}
			passphrase = pass
		}
	}

	// Step 4: Generate shares
	fmt.Println()
	cyan.Println("Step 4: Generating shares...")
	fmt.Println()

	mnemonics, err := slip039.SplitMasterSecret(
		masterSecret,
		passphrase,
		groupThreshold,
		groups,
	)
	if err != nil {
		return fmt.Errorf("failed to split secret: %w", err)
	}

	green.Println("✓ Shares generated successfully!")

	// Step 5: Test recovery
	if !testMode {
		fmt.Println()
		cyan.Println("Step 5: Test recovery (IMPORTANT!)")
		fmt.Println()
		fmt.Println("Let's verify the shares work by testing recovery.")
		fmt.Println("Enter the minimum required shares to test:")
		fmt.Println()

		var testShares []string
		if len(groups) == 1 {
			// Simple mode
			for i := 0; i < int(groups[0].MemberThreshold); i++ {
				fmt.Printf("Enter share %d of %d:\n", i+1, groups[0].MemberThreshold)
				fmt.Print("> ")
				share, _ := reader.ReadString('\n')
				share = strings.TrimSpace(share)
				testShares = append(testShares, share)
			}
		} else {
			fmt.Println("Enter shares from different groups:")
			for i := 0; i < int(groupThreshold); i++ {
				fmt.Printf("Enter a share from group %d:\n", i+1)
				fmt.Print("> ")
				share, _ := reader.ReadString('\n')
				share = strings.TrimSpace(share)
				testShares = append(testShares, share)
			}
		}

		recovered, err := slip039.RecoverMasterSecret(testShares, passphrase)
		if err != nil {
			red.Printf("❌ Recovery failed: %v\n", err)
			fmt.Println("Please check your shares and try again.")
			return err
		}

		// Verify it matches
		if hex.EncodeToString(recovered[:16]) == hex.EncodeToString(masterSecret[:16]) {
			green.Println("✅ Recovery test PASSED! Your shares are valid.")
		} else {
			red.Println("❌ Recovery test FAILED! Shares don't match original.")
			return fmt.Errorf("recovery verification failed")
		}
	}

	// Step 6: Save or display shares
	fmt.Println()
	cyan.Println("Step 6: How do you want to handle your shares?")
	fmt.Println()
	
	red.Println("⚠️  SECURITY WARNING:")
	fmt.Println("Saving shares to disk creates security risks:")
	fmt.Println("• Files can be recovered even after deletion")
	fmt.Println("• Cloud backups might sync these files")
	fmt.Println("• Malware could steal these files")
	fmt.Println()
	
	fmt.Println("1. Display on screen only (RECOMMENDED)")
	fmt.Println("2. Save to files (RISKY - only for temporary use)")
	fmt.Println("3. Display AND save (for immediate printing)")
	fmt.Println()
	fmt.Print("Choice [1]: ")
	
	saveChoice, _ := reader.ReadString('\n')
	saveChoice = strings.TrimSpace(saveChoice)
	if saveChoice == "" {
		saveChoice = "1"
	}
	
	saveToFile := saveChoice == "2" || saveChoice == "3"
	displayShares := saveChoice == "1" || saveChoice == "3"
	
	if saveToFile {
		red.Println("\n⚠️  You chose to save to files. IMPORTANT:")
		fmt.Println("• Delete these files immediately after use")
		fmt.Println("• Use secure deletion tools (shred on Linux)")
		fmt.Println("• Never store on networked or cloud-synced drives")
		fmt.Println("• Consider using full disk encryption")
		fmt.Println()
		fmt.Print("Press Enter to continue with file storage...")
		reader.ReadString('\n')
		
		if outputDir == "" {
			outputDir = fmt.Sprintf("shamir-backup-%s", time.Now().Format("2006-01-02-150405"))
		}

		if err := os.MkdirAll(outputDir, 0700); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Display shares if requested
	if displayShares {
		fmt.Println()
		green.Println("=== YOUR SHARES ===")
		fmt.Println()
		red.Println("⚠️  WRITE THESE DOWN CAREFULLY!")
		fmt.Println("Double-check each word. A single mistake can make recovery impossible.")
		fmt.Println()
		
		shareNum := 1
		for groupIdx, group := range mnemonics {
			for memberIdx, share := range group {
				yellow.Printf("Share %d (Group %d, Member %d):\n", shareNum, groupIdx+1, memberIdx+1)
				fmt.Println(strings.Repeat("-", 60))
				
				// Display share in chunks for easier transcription
				words := strings.Fields(share)
				for i := 0; i < len(words); i += 4 {
					end := i + 4
					if end > len(words) {
						end = len(words)
					}
					fmt.Printf("  %s\n", strings.Join(words[i:end], " "))
				}
				fmt.Println(strings.Repeat("-", 60))
				fmt.Println()
				shareNum++
			}
		}
		
		fmt.Println("Press Enter when you've written down all shares...")
		reader.ReadString('\n')
	}
	
	// Save to files if requested
	if saveToFile {
		// Save metadata
		metadata := map[string]interface{}{
			"created":        time.Now().Format(time.RFC3339),
			"type":          sourceType,
			"description":   description,
			"groupThreshold": groupThreshold,
			"groups":        groups,
			"hasPassphrase": passphrase != "",
			"WARNING":       "DELETE THESE FILES AFTER USE - SECURITY RISK!",
		}

		metadataPath := filepath.Join(outputDir, "backup-info.json")
		metadataFile, err := os.Create(metadataPath)
		if err != nil {
			return err
		}
		json.NewEncoder(metadataFile).Encode(metadata)
		metadataFile.Close()

		// Save shares to individual files
		shareNum := 1
		for groupIdx, group := range mnemonics {
			for memberIdx, share := range group {
				filename := fmt.Sprintf("share-%d-%d.txt", groupIdx+1, memberIdx+1)
				sharePath := filepath.Join(outputDir, filename)
				
				content := fmt.Sprintf("SLIP-0039 Share\n")
				content += fmt.Sprintf("⚠️  SECURITY WARNING: DELETE THIS FILE AFTER USE!\n")
				content += fmt.Sprintf("Group: %d of %d\n", groupIdx+1, len(groups))
				content += fmt.Sprintf("Member: %d\n", memberIdx+1)
				content += fmt.Sprintf("Created: %s\n", time.Now().Format("2006-01-02"))
				content += fmt.Sprintf("\n%s\n", share)
				
				if err := os.WriteFile(sharePath, []byte(content), 0600); err != nil {
					return err
				}
				
				fmt.Printf("  ✓ Saved %s\n", filename)
				shareNum++
			}
		}
		
		// Create a deletion script
		scriptPath := filepath.Join(outputDir, "DELETE_SHARES.sh")
		script := fmt.Sprintf(`#!/bin/bash
# SECURE DELETION SCRIPT
echo "This will securely delete all share files."
echo "Make sure you have backed up shares physically first!"
read -p "Are you sure? (yes/no): " confirm
if [ "$confirm" = "yes" ]; then
    # Use shred if available, otherwise rm
    if command -v shred &> /dev/null; then
        shred -vfz -n 3 %s/*.txt %s/*.json
    else
        rm -f %s/*.txt %s/*.json
    fi
    rm -rf %s
    echo "Shares deleted."
else
    echo "Cancelled."
fi
`, outputDir, outputDir, outputDir, outputDir, outputDir)
		os.WriteFile(scriptPath, []byte(script), 0700)
	}

	// Final instructions
	fmt.Println()
	green.Println("🎉 BACKUP COMPLETE!")
	fmt.Println()
	yellow.Println("📋 CRITICAL SECURITY STEPS:")
	fmt.Println()
	
	if saveToFile {
		red.Println("⚠️  FILES SAVED - IMMEDIATE ACTION REQUIRED:")
		fmt.Println("1. Transfer shares to physical medium NOW")
		fmt.Println("2. Verify physical copies are correct")
		fmt.Printf("3. Run the deletion script: %s/DELETE_SHARES.sh\n", outputDir)
		fmt.Println("4. Or manually secure delete:")
		fmt.Printf("   shred -vfz -n 3 %s/*\n", outputDir)
		fmt.Printf("   rm -rf %s\n", outputDir)
		fmt.Println()
		red.Println("⚠️  DO NOT:")
		fmt.Println("• Leave files on disk")
		fmt.Println("• Copy to cloud storage")
		fmt.Println("• Email or message shares")
		fmt.Println("• Take photos of shares")
		fmt.Println()
	}
	
	yellow.Println("📋 STORAGE BEST PRACTICES:")
	fmt.Println()
	fmt.Println("1. Use PHYSICAL storage only:")
	fmt.Println("   • Paper in waterproof sleeves")
	fmt.Println("   • Laminated cards")
	fmt.Println("   • Steel plates (fire-resistant)")
	fmt.Println()
	fmt.Println("2. Distribute to DIFFERENT locations:")
	fmt.Println("   • Home safe")
	fmt.Println("   • Bank safety deposit box")
	fmt.Println("   • Trusted family (different households)")
	fmt.Println("   • Attorney/executor")
	fmt.Println()
	fmt.Println("3. NEVER store digitally:")
	fmt.Println("   ❌ Cloud storage")
	fmt.Println("   ❌ Password managers")
	fmt.Println("   ❌ Email")
	fmt.Println("   ❌ Photos on phone")
	fmt.Println()
	
	if passphrase != "" {
		red.Println("⚠️  PASSPHRASE REQUIRED FOR RECOVERY!")
		fmt.Println("• Memorize it or store separately from shares")
		fmt.Println("• Consider sharing with trusted executor")
		fmt.Println("• Without it, shares are useless")
	}

	return nil
}

func parseInt(s string, defaultVal int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return defaultVal
	}
	return n
}