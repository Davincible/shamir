package cli

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/slip039"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// NewRestoreCommand creates an interactive restore wizard
func NewRestoreCommand() *cobra.Command {
	var (
		inputDir string
		outputFile string
	)

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Interactive wizard to restore a secret from shares",
		Long: `An interactive wizard that guides you through restoring your secret
from SLIP-0039 shares. Handles both simple and group-based sharing.`,
		Example: `  # Start interactive restore wizard
  shamir restore

  # Restore from backup directory
  shamir restore --input ~/backups/shamir-backup-2024

  # Save recovered secret to file
  shamir restore --output recovered-secret.txt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRestoreWizard(inputDir, outputFile)
		},
	}

	cmd.Flags().StringVarP(&inputDir, "input", "i", "", "Directory containing share files")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "File to save recovered secret")

	return cmd
}

func runRestoreWizard(inputDir, outputFile string) error {
	reader := bufio.NewReader(os.Stdin)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)
	red := color.New(color.FgRed, color.Bold)

	// Welcome message
	fmt.Println()
	green.Println("🔓 SHAMIR SECRET RESTORE WIZARD")
	fmt.Println("=" + strings.Repeat("=", 40))
	fmt.Println()

	var shares []string
	var passphrase string
	var metadata map[string]interface{}

	// Check if we have a backup directory
	if inputDir != "" {
		// Try to load metadata
		metadataPath := filepath.Join(inputDir, "backup-info.json")
		if metadataFile, err := os.Open(metadataPath); err == nil {
			json.NewDecoder(metadataFile).Decode(&metadata)
			metadataFile.Close()
			
			cyan.Println("Found backup information:")
			fmt.Printf("  Created: %v\n", metadata["created"])
			fmt.Printf("  Type: %v\n", metadata["type"])
			fmt.Printf("  Description: %v\n", metadata["description"])
			if metadata["hasPassphrase"].(bool) {
				fmt.Println("  Passphrase: Required")
			}
			fmt.Println()
		}

		// Load share files
		shareFiles, err := filepath.Glob(filepath.Join(inputDir, "share-*.txt"))
		if err == nil && len(shareFiles) > 0 {
			yellow.Printf("Found %d share files in %s\n", len(shareFiles), inputDir)
			fmt.Println()
			fmt.Print("Load all shares from this directory? [Y/n]: ")
			
			loadChoice, _ := reader.ReadString('\n')
			loadChoice = strings.TrimSpace(strings.ToLower(loadChoice))
			
			if loadChoice != "n" && loadChoice != "no" {
				for _, file := range shareFiles {
					content, err := os.ReadFile(file)
					if err != nil {
						continue
					}
					
					// Extract mnemonic from file (last non-empty line)
					lines := strings.Split(string(content), "\n")
					for i := len(lines) - 1; i >= 0; i-- {
						line := strings.TrimSpace(lines[i])
						if line != "" && strings.Count(line, " ") >= 19 {
							shares = append(shares, line)
							fmt.Printf("  ✓ Loaded %s\n", filepath.Base(file))
							break
						}
					}
				}
			}
		}
	}

	// Manual share entry
	if len(shares) == 0 {
		cyan.Println("Step 1: Enter your SLIP-0039 shares")
		fmt.Println()
		fmt.Println("Enter each share (20 or 33 words), one per line.")
		fmt.Println("Press Enter twice when done.")
		fmt.Println()

		for {
			fmt.Printf("Share %d: ", len(shares)+1)
			share, _ := reader.ReadString('\n')
			share = strings.TrimSpace(share)
			
			if share == "" {
				if len(shares) > 0 {
					break
				}
				continue
			}

			// Validate share
			if err := slip039.ValidateMnemonic(share); err != nil {
				red.Printf("  ❌ Invalid share: %v\n", err)
				continue
			}

			shares = append(shares, share)
			green.Printf("  ✓ Valid share (Total: %d)\n", len(shares))

			// Show share info
			if info, err := slip039.GetShareInfo(share); err == nil {
				if len(shares) == 1 {
					// First share, show requirements
					fmt.Printf("     Group %d needs %d members\n", 
						info.GroupIndex, info.MemberThreshold)
					if info.GroupCount > 1 {
						fmt.Printf("     Need shares from %d of %d groups\n",
							info.GroupThreshold, info.GroupCount)
					}
				}
			}
		}
	}

	if len(shares) == 0 {
		return fmt.Errorf("no shares provided")
	}

	fmt.Println()
	cyan.Printf("Collected %d shares\n", len(shares))

	// Check if we have metadata about passphrase
	needsPassphrase := false
	if metadata != nil {
		if hasPass, ok := metadata["hasPassphrase"].(bool); ok && hasPass {
			needsPassphrase = true
		}
	}

	// Step 2: Passphrase
	fmt.Println()
	if needsPassphrase {
		cyan.Println("Step 2: Enter passphrase (required)")
	} else {
		cyan.Println("Step 2: Enter passphrase (if any)")
		fmt.Println("Press Enter if no passphrase was used.")
	}
	fmt.Println()

	pass, err := readPassphrase("Passphrase: ")
	if err != nil {
		return err
	}
	passphrase = pass

	// Step 3: Attempt recovery
	fmt.Println()
	cyan.Println("Step 3: Attempting recovery...")
	fmt.Println()

	recovered, err := slip039.RecoverMasterSecret(shares, passphrase)
	if err != nil {
		red.Printf("❌ Recovery failed: %v\n", err)
		fmt.Println()
		fmt.Println("Common issues:")
		fmt.Println("- Not enough shares provided")
		fmt.Println("- Wrong passphrase")
		fmt.Println("- Shares from different secrets mixed")
		fmt.Println("- Corrupted or modified shares")
		return err
	}

	green.Println("✅ SECRET SUCCESSFULLY RECOVERED!")
	fmt.Println()

	// Step 4: Display or save the recovered secret
	if outputFile != "" {
		if err := os.WriteFile(outputFile, recovered, 0600); err != nil {
			return fmt.Errorf("failed to save to file: %w", err)
		}
		green.Printf("✓ Saved to %s\n", outputFile)
	} else {
		yellow.Println("Recovered Secret:")
		fmt.Println()
		
		// Display as hex
		fmt.Println("Hex format:")
		hexStr := hex.EncodeToString(recovered)
		fmt.Println(hexStr)
		fmt.Println()
		
		// If it looks like text, show it
		isPrintable := true
		for _, b := range recovered {
			if b < 32 || b > 126 {
				isPrintable = false
				break
			}
		}
		
		if isPrintable {
			fmt.Println("Text format:")
			fmt.Println(string(recovered))
			fmt.Println()
		}
		
		// Show size
		fmt.Printf("Size: %d bytes\n", len(recovered))
		
		// Check if it might be a BIP-39 seed
		if len(recovered) == 64 {
			fmt.Println()
			cyan.Println("This appears to be a BIP-39 seed (64 bytes).")
			fmt.Println("You can use it with HD wallet software to derive keys.")
		}
	}

	fmt.Println()
	red.Println("⚠️  SECURITY WARNING:")
	fmt.Println("- Clear your terminal history after viewing")
	fmt.Println("- Securely delete any temporary files")
	fmt.Println("- Never share this secret or store it unencrypted")
	
	return nil
}