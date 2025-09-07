package cli

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/slip039"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func NewSlip039Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "slip039",
		Short: "SLIP-0039 Shamir's Secret Sharing operations",
		Long: `SLIP-0039 implements a hierarchical Shamir's Secret Sharing scheme
with two-level sharing (groups and members), encryption, and mnemonic encoding.

This is compatible with Trezor and other hardware wallets that support SLIP-0039.`,
	}

	cmd.AddCommand(
		newSlip039SplitCommand(),
		newSlip039CombineCommand(),
		newSlip039InfoCommand(),
	)

	return cmd
}

func newSlip039SplitCommand() *cobra.Command {
	var (
		simpleMode      bool
		threshold       int
		shares          int
		groupThreshold  int
		groupsSpec      string
		passphrase      string
		secretHex       string
		secretLength    int
	)

	cmd := &cobra.Command{
		Use:   "split",
		Short: "Split a secret using SLIP-0039",
		Long: `Split a master secret into SLIP-0039 mnemonic shares.

Simple mode creates a single group with T-of-N sharing.
Advanced mode allows multiple groups with different thresholds.

Examples:
  # Simple 2-of-3 sharing
  shamir slip039 split --simple --threshold 2 --shares 3

  # Two groups: (2-of-3) and (3-of-5), need both groups
  shamir slip039 split --group-threshold 2 --groups "2/3,3/5"

  # Generate random 256-bit secret and split
  shamir slip039 split --simple --threshold 3 --shares 5 --length 32`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse configuration
			var groups []slip039.GroupConfiguration
			var actualGroupThreshold byte

			if simpleMode {
				if threshold <= 0 || shares <= 0 {
					return fmt.Errorf("threshold and shares must be positive in simple mode")
				}
				groups = slip039.SimpleConfiguration(byte(threshold), byte(shares))
				actualGroupThreshold = 1
			} else {
				if groupsSpec == "" {
					return fmt.Errorf("groups specification required in advanced mode")
				}
				
				parsedGroups, err := parseGroupsSpec(groupsSpec)
				if err != nil {
					return fmt.Errorf("invalid groups specification: %w", err)
				}
				groups = parsedGroups
				
				if groupThreshold <= 0 || groupThreshold > len(groups) {
					return fmt.Errorf("group-threshold must be between 1 and %d", len(groups))
				}
				actualGroupThreshold = byte(groupThreshold)
			}

			// Get or generate master secret
			var masterSecret []byte
			if secretHex != "" {
				decoded, err := hex.DecodeString(secretHex)
				if err != nil {
					return fmt.Errorf("invalid hex secret: %w", err)
				}
				masterSecret = decoded
			} else if secretLength > 0 {
				generated, err := slip039.GenerateMasterSecret(secretLength)
				if err != nil {
					return fmt.Errorf("failed to generate secret: %w", err)
				}
				masterSecret = generated
				
				fmt.Printf("Generated master secret: %x\n\n", masterSecret)
			} else {
				// Read secret interactively
				secret, err := readSecretInteractive()
				if err != nil {
					return err
				}
				masterSecret = secret
			}

			// Get passphrase if not provided
			if passphrase == "" && !cmd.Flags().Changed("passphrase") {
				pass, err := readPassphrase("Enter passphrase (optional, press Enter to skip): ")
				if err != nil {
					return err
				}
				passphrase = pass
			}

			// Split the secret
			mnemonics, err := slip039.SplitMasterSecret(
				masterSecret,
				passphrase,
				actualGroupThreshold,
				groups,
			)
			if err != nil {
				return fmt.Errorf("failed to split secret: %w", err)
			}

			// Display results
			displaySlip039Shares(mnemonics, actualGroupThreshold, groups)

			return nil
		},
	}

	cmd.Flags().BoolVar(&simpleMode, "simple", false, "Use simple T-of-N sharing (single group)")
	cmd.Flags().IntVarP(&threshold, "threshold", "t", 0, "Member threshold for simple mode")
	cmd.Flags().IntVarP(&shares, "shares", "n", 0, "Number of shares for simple mode")
	cmd.Flags().IntVar(&groupThreshold, "group-threshold", 1, "Number of groups required (advanced mode)")
	cmd.Flags().StringVar(&groupsSpec, "groups", "", "Groups specification (e.g., '2/3,3/5' for two groups)")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Passphrase for encryption")
	cmd.Flags().StringVar(&secretHex, "secret", "", "Master secret in hex")
	cmd.Flags().IntVarP(&secretLength, "length", "l", 0, "Generate random secret of specified bytes (16 or 32)")

	return cmd
}

func newSlip039CombineCommand() *cobra.Command {
	var (
		mnemonicsFile string
		passphrase    string
		outputHex     bool
	)

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combine SLIP-0039 shares to recover secret",
		Long: `Combine SLIP-0039 mnemonic shares to recover the original master secret.

Enter shares interactively or provide them in a file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read mnemonics
			var mnemonics []string
			
			if mnemonicsFile != "" {
				loaded, err := readMnemonicsFromFile(mnemonicsFile)
				if err != nil {
					return err
				}
				mnemonics = loaded
			} else {
				collected, err := collectMnemonicsInteractive()
				if err != nil {
					return err
				}
				mnemonics = collected
			}

			if len(mnemonics) == 0 {
				return fmt.Errorf("no mnemonics provided")
			}

			// Get passphrase if not provided
			if passphrase == "" && !cmd.Flags().Changed("passphrase") {
				pass, err := readPassphrase("Enter passphrase (press Enter if none): ")
				if err != nil {
					return err
				}
				passphrase = pass
			}

			// Combine shares
			masterSecret, err := slip039.RecoverMasterSecret(mnemonics, passphrase)
			if err != nil {
				return fmt.Errorf("failed to recover secret: %w", err)
			}

			// Display result
			green := color.New(color.FgGreen, color.Bold)
			green.Println("\n✓ Successfully recovered master secret!")
			
			if outputHex {
				fmt.Printf("\nMaster Secret (hex): %x\n", masterSecret)
			} else {
				fmt.Printf("\nMaster Secret: %s\n", string(masterSecret))
				fmt.Printf("            (hex): %x\n", masterSecret)
			}

			// Clear sensitive data
			for i := range masterSecret {
				masterSecret[i] = 0
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&mnemonicsFile, "file", "f", "", "File containing mnemonics (one per line)")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Passphrase used during splitting")
	cmd.Flags().BoolVar(&outputHex, "hex", false, "Output only as hexadecimal")

	return cmd
}

func newSlip039InfoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Display information about a SLIP-0039 share",
		Long:  `Display detailed information about a SLIP-0039 mnemonic share.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read mnemonic
			fmt.Println("Enter SLIP-0039 mnemonic share:")
			reader := bufio.NewReader(os.Stdin)
			mnemonic, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			mnemonic = strings.TrimSpace(mnemonic)

			// Validate and get info
			if err := slip039.ValidateMnemonic(mnemonic); err != nil {
				return fmt.Errorf("invalid mnemonic: %w", err)
			}

			info, err := slip039.GetShareInfo(mnemonic)
			if err != nil {
				return fmt.Errorf("failed to get share info: %w", err)
			}

			// Display info
			cyan := color.New(color.FgCyan, color.Bold)
			cyan.Println("\n=== SLIP-0039 Share Information ===\n")
			
			fmt.Println(info.String())
			
			// Display word count
			words := strings.Fields(mnemonic)
			fmt.Printf("\nWord Count: %d\n", len(words))

			return nil
		},
	}

	return cmd
}

func parseGroupsSpec(spec string) ([]slip039.GroupConfiguration, error) {
	parts := strings.Split(spec, ",")
	groups := make([]slip039.GroupConfiguration, len(parts))
	
	for i, part := range parts {
		part = strings.TrimSpace(part)
		thresholdAndCount := strings.Split(part, "/")
		
		if len(thresholdAndCount) != 2 {
			return nil, fmt.Errorf("invalid group spec '%s', expected format: threshold/count", part)
		}
		
		threshold, err := strconv.Atoi(thresholdAndCount[0])
		if err != nil || threshold <= 0 || threshold > 16 {
			return nil, fmt.Errorf("invalid threshold in '%s'", part)
		}
		
		count, err := strconv.Atoi(thresholdAndCount[1])
		if err != nil || count <= 0 || count > 16 {
			return nil, fmt.Errorf("invalid count in '%s'", part)
		}
		
		if threshold > count {
			return nil, fmt.Errorf("threshold cannot exceed count in '%s'", part)
		}
		
		groups[i] = slip039.GroupConfiguration{
			MemberThreshold: byte(threshold),
			MemberCount:     byte(count),
		}
	}
	
	return groups, nil
}

func displaySlip039Shares(mnemonics [][]string, groupThreshold byte, groups []slip039.GroupConfiguration) {
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	
	fmt.Println()
	yellow.Println("=== SLIP-0039 MNEMONIC SHARES ===")
	fmt.Println()
	
	if len(groups) == 1 {
		// Simple mode
		green.Printf("Created %d shares with threshold %d\n", 
			groups[0].MemberCount, groups[0].MemberThreshold)
		fmt.Printf("Any %d shares can reconstruct the original secret\n\n", 
			groups[0].MemberThreshold)
	} else {
		// Advanced mode
		green.Printf("Created %d groups with group threshold %d\n", 
			len(groups), groupThreshold)
		fmt.Printf("Need shares from at least %d groups to reconstruct\n\n", 
			groupThreshold)
	}
	
	for i, group := range mnemonics {
		if len(groups) > 1 {
			cyan.Printf("Group %d (threshold %d of %d):\n", 
				i+1, groups[i].MemberThreshold, groups[i].MemberCount)
		}
		
		for j, share := range group {
			fmt.Printf("\nShare %d-%d:\n", i+1, j+1)
			
			// Display share with word numbers
			words := strings.Fields(share)
			for k := 0; k < len(words); k += 4 {
				end := k + 4
				if end > len(words) {
					end = len(words)
				}
				fmt.Printf("  %s\n", strings.Join(words[k:end], " "))
			}
		}
		
		if len(groups) > 1 {
			fmt.Println()
		}
	}
	
	fmt.Println()
	red.Println("⚠️  SECURITY WARNING:")
	fmt.Println("- Each share should be stored in a different secure location")
	fmt.Println("- Never store shares together or electronically without encryption")
	fmt.Println("- Test recovery with minimum shares before relying on this backup")
	fmt.Println("- These shares are SLIP-0039 compatible (Trezor Model T, etc.)")
}

func collectMnemonicsInteractive() ([]string, error) {
	fmt.Println("Enter SLIP-0039 mnemonic shares (one per line).")
	fmt.Println("Press Enter twice when done.")
	fmt.Println()
	
	reader := bufio.NewReader(os.Stdin)
	var mnemonics []string
	shareNum := 1
	
	for {
		fmt.Printf("Share %d: ", shareNum)
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		
		line = strings.TrimSpace(line)
		if line == "" {
			if len(mnemonics) == 0 {
				continue // Don't break on first empty line
			}
			break
		}
		
		// Validate mnemonic
		if err := slip039.ValidateMnemonic(line); err != nil {
			fmt.Printf("  ✗ Invalid share: %v\n", err)
			continue
		}
		
		mnemonics = append(mnemonics, line)
		fmt.Println("  ✓ Valid share added")
		shareNum++
	}
	
	return mnemonics, nil
}

func readMnemonicsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var mnemonics []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		mnemonics = append(mnemonics, line)
	}
	
	return mnemonics, scanner.Err()
}

func readPassphrase(prompt string) (string, error) {
	fmt.Print(prompt)
	
	if term.IsTerminal(int(os.Stdin.Fd())) {
		passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(passBytes), nil
	}
	
	// Fallback for non-terminal
	reader := bufio.NewReader(os.Stdin)
	pass, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(pass), nil
}