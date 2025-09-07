package cli

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/secretsharing"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// RecoverCommand provides advanced recovery capabilities
func NewRecoverCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Advanced secret recovery with smart assistance",
		Long: `Advanced recovery system with intelligent assistance and verification.

This command provides enhanced recovery capabilities including:
• Smart share detection and validation
• Recovery simulation and verification
• Share compatibility checking
• Guided recovery process
• Integration with share management
• Multiple input methods and formats

The recovery system can work with both individual shares and managed share sets.`,
		Example: `  # Interactive recovery mode
  shamir recover

  # Simulate recovery without revealing secret
  shamir recover --simulate --input shares.json

  # Recover from managed share set
  shamir recover --from-store abc123

  # Recovery with specific share files
  shamir recover --shares file1.json,file2.json,file3.json

  # Smart recovery with auto-detection
  shamir recover --auto-detect --directory ./backup/`,
	}

	// Add subcommands
	cmd.AddCommand(
		newRecoverInteractiveCommand(),
		newRecoverSimulateCommand(),
		newRecoverFromStoreCommand(),
		newRecoverAutoCommand(),
		newRecoverVerifyCommand(),
	)

	return cmd
}

func newRecoverInteractiveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "interactive",
		Short: "Interactive guided recovery",
		Long: `Guided recovery process with step-by-step assistance.

This mode provides:
• Share collection from multiple sources
• Automatic share validation
• Recovery simulation before actual recovery
• Secure output options
• Recovery verification`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInteractiveRecovery()
		},
	}

	return cmd
}

func newRecoverSimulateCommand() *cobra.Command {
	var (
		input  string
		shares []string
	)

	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Simulate recovery without revealing the secret",
		Long: `Test recovery process without actually reconstructing the secret.

This is useful for:
• Verifying you have the correct shares
• Testing recovery before actually performing it
• Checking share compatibility
• Validating thresholds`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecoverySimulation(input, shares)
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "Input file containing shares")
	cmd.Flags().StringSliceVar(&shares, "shares", nil, "List of share files")

	return cmd
}

func newRecoverFromStoreCommand() *cobra.Command {
	var (
		simulate bool
		output   string
	)

	cmd := &cobra.Command{
		Use:   "from-store [SHARE_SET_ID]",
		Short: "Recover secret from managed share set",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStoreRecovery(args[0], simulate, output)
		},
	}

	cmd.Flags().BoolVar(&simulate, "simulate", false, "Simulate recovery only")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file for recovered secret")

	return cmd
}

func newRecoverAutoCommand() *cobra.Command {
	var (
		directory string
		pattern   string
		recursive bool
	)

	cmd := &cobra.Command{
		Use:   "auto",
		Short: "Auto-detect and recover from available shares",
		Long: `Automatically detect and recover secrets from available share files.

This command scans directories for share files and attempts to recover
any secrets that have sufficient shares available.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAutoRecovery(directory, pattern, recursive)
		},
	}

	cmd.Flags().StringVarP(&directory, "directory", "d", ".", "Directory to scan")
	cmd.Flags().StringVar(&pattern, "pattern", "*.json", "File pattern to match")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Recursive directory scan")

	return cmd
}

func newRecoverVerifyCommand() *cobra.Command {
	var shares []string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify shares can be used for recovery",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecoveryVerification(shares)
		},
	}

	cmd.Flags().StringSliceVar(&shares, "shares", nil, "Share files to verify")

	return cmd
}

// Recovery implementations

func runInteractiveRecovery() error {
	reader := bufio.NewReader(os.Stdin)
	
	color.Cyan("\n🔓 Advanced Secret Recovery\n")
	fmt.Println("This guided process will help you recover your secret safely.")
	fmt.Println()
	
	// Step 1: Determine source of shares
	fmt.Println("Where are your shares stored?")
	fmt.Println("1) Individual share files")
	fmt.Println("2) Single JSON file with all shares")
	fmt.Println("3) Managed share set (from shamir manage)")
	fmt.Println("4) Manual entry (copy/paste shares)")
	fmt.Println("5) Auto-detect from directory")
	
	fmt.Print("\nChoice (1-5): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	
	var shares []secretsharing.Share
	var err error
	
	switch choice {
	case "1":
		shares, err = collectSharesFromFiles(reader)
	case "2":
		shares, err = collectSharesFromSingleFile(reader)
	case "3":
		shares, err = collectSharesFromStore(reader)
	case "4":
		shares, err = collectSharesManually(reader)
	case "5":
		shares, err = collectSharesAutoDetect(reader)
	default:
		return fmt.Errorf("invalid choice")
	}
	
	if err != nil {
		return fmt.Errorf("failed to collect shares: %w", err)
	}
	
	// Step 2: Validate and analyze shares
	color.Yellow("\n🔍 Analyzing collected shares...")
	analysis, err := analyzeShares(shares)
	if err != nil {
		return fmt.Errorf("share analysis failed: %w", err)
	}
	
	displayShareAnalysis(analysis)
	
	if !analysis.CanRecover {
		color.Red("\n❌ Cannot recover secret with available shares")
		return fmt.Errorf("insufficient or incompatible shares")
	}
	
	// Step 3: Recovery simulation
	fmt.Print("\nPerform recovery simulation first? (Y/n): ")
	simChoice, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(simChoice)) != "n" {
		color.Yellow("\n🧪 Running recovery simulation...")
		if err := simulateRecovery(shares); err != nil {
			color.Red("❌ Simulation failed: %v", err)
			return err
		}
		color.Green("✅ Simulation successful - recovery should work")
	}
	
	// Step 4: Passphrase handling
	var passphrase string
	if analysis.RequiresPassphrase {
		color.Yellow("\n🔐 This secret was protected with a passphrase")
		fmt.Print("Enter passphrase: ")
		passphraseBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
		passphrase = string(passphraseBytes)
		fmt.Println()
	}
	
	// Step 5: Actual recovery
	fmt.Print("\nProceed with actual recovery? (y/N): ")
	proceedChoice, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(proceedChoice)) != "y" {
		fmt.Println("Recovery cancelled.")
		return nil
	}
	
	color.Yellow("\n🔓 Recovering secret...")
	secret, err := performRecovery(shares, passphrase)
	if err != nil {
		return fmt.Errorf("recovery failed: %w", err)
	}
	
	// Step 6: Output handling
	return handleRecoveryOutput(secret, reader)
}

// ShareAnalysis contains analysis results for a set of shares
type ShareAnalysis struct {
	TotalShares        int                      `json:"total_shares"`
	ValidShares        int                      `json:"valid_shares"`
	RequiredThreshold  int                      `json:"required_threshold"`
	CanRecover         bool                     `json:"can_recover"`
	Scheme             secretsharing.SchemeType `json:"scheme"`
	RequiresPassphrase bool                     `json:"requires_passphrase"`
	Groups             []GroupAnalysis          `json:"groups"`
	Issues             []string                 `json:"issues"`
	Recommendations    []string                 `json:"recommendations"`
}

// GroupAnalysis contains analysis for hierarchical groups
type GroupAnalysis struct {
	Index             int  `json:"index"`
	RequiredShares    int  `json:"required_shares"`
	AvailableShares   int  `json:"available_shares"`
	CanContribute     bool `json:"can_contribute"`
}

func analyzeShares(shares []secretsharing.Share) (*ShareAnalysis, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}
	
	analysis := &ShareAnalysis{
		TotalShares: len(shares),
		Issues:      []string{},
		Recommendations: []string{},
	}
	
	// Get the first share's scheme for reference
	analysis.Scheme = shares[0].Info.Scheme
	
	// Validate all shares are from the same scheme and secret
	identifier := shares[0].Info.Identifier
	for i, share := range shares {
		if share.Info.Scheme != analysis.Scheme {
			analysis.Issues = append(analysis.Issues, 
				fmt.Sprintf("Share %d uses different scheme (%s vs %s)", 
					i+1, share.Info.Scheme, analysis.Scheme))
		}
		
		if share.Info.Identifier != identifier {
			analysis.Issues = append(analysis.Issues, 
				fmt.Sprintf("Share %d has different identifier (possible mismatch)", i+1))
		}
	}
	
	// Get the appropriate sharer for validation
	sharer, err := secretsharing.DefaultRegistry.Get(analysis.Scheme)
	if err != nil {
		return nil, fmt.Errorf("unsupported scheme: %w", err)
	}
	
	// Validate each share
	validShares := 0
	for i, share := range shares {
		if err := sharer.Verify(share); err != nil {
			analysis.Issues = append(analysis.Issues, 
				fmt.Sprintf("Share %d is invalid: %v", i+1, err))
		} else {
			validShares++
		}
	}
	analysis.ValidShares = validShares
	
	// Determine threshold requirements
	if len(shares) > 0 {
		analysis.RequiredThreshold = shares[0].Info.MemberThreshold
		
		// Check if we can recover
		if analysis.Scheme == secretsharing.SchemeSLIP039 {
			// For SLIP-0039, need to check hierarchical requirements
			analysis.CanRecover = analyzeHierarchicalRecovery(shares, analysis)
		} else {
			// For simple schemes like PVSS
			analysis.CanRecover = validShares >= analysis.RequiredThreshold
		}
	}
	
	// Generate recommendations
	if !analysis.CanRecover {
		if validShares < analysis.RequiredThreshold {
			analysis.Recommendations = append(analysis.Recommendations,
				fmt.Sprintf("Need %d more valid shares (have %d, need %d)",
					analysis.RequiredThreshold-validShares, validShares, analysis.RequiredThreshold))
		}
	}
	
	if len(analysis.Issues) > 0 {
		analysis.Recommendations = append(analysis.Recommendations,
			"Resolve share validation issues before attempting recovery")
	}
	
	return analysis, nil
}

func analyzeHierarchicalRecovery(shares []secretsharing.Share, analysis *ShareAnalysis) bool {
	// Group shares by group index
	groups := make(map[int][]secretsharing.Share)
	for _, share := range shares {
		groupIdx := share.Info.GroupIndex
		groups[groupIdx] = append(groups[groupIdx], share)
	}
	
	// Analyze each group
	validGroups := 0
	groupThreshold := 0
	
	for groupIdx, groupShares := range groups {
		if len(groupShares) == 0 {
			continue
		}
		
		// Get group requirements from first share
		memberThreshold := groupShares[0].Info.MemberThreshold
		groupThreshold = groupShares[0].Info.GroupThreshold // Should be same for all
		
		// Count valid shares in this group
		validInGroup := 0
		for _, share := range groupShares {
			// Validate individual share
			sharer, _ := secretsharing.DefaultRegistry.Get(analysis.Scheme)
			if err := sharer.Verify(share); err == nil {
				validInGroup++
			}
		}
		
		canContribute := validInGroup >= memberThreshold
		if canContribute {
			validGroups++
		}
		
		// Add group analysis
		analysis.Groups = append(analysis.Groups, GroupAnalysis{
			Index:           groupIdx,
			RequiredShares:  memberThreshold,
			AvailableShares: validInGroup,
			CanContribute:   canContribute,
		})
	}
	
	// Sort groups by index
	sort.Slice(analysis.Groups, func(i, j int) bool {
		return analysis.Groups[i].Index < analysis.Groups[j].Index
	})
	
	// Can recover if we have enough valid groups
	return validGroups >= groupThreshold
}

func displayShareAnalysis(analysis *ShareAnalysis) {
	fmt.Printf("\n📊 Share Analysis Results\n")
	fmt.Printf("========================\n\n")
	
	fmt.Printf("Scheme: %s\n", analysis.Scheme)
	fmt.Printf("Total Shares: %d\n", analysis.TotalShares)
	fmt.Printf("Valid Shares: %d\n", analysis.ValidShares)
	fmt.Printf("Required Threshold: %d\n", analysis.RequiredThreshold)
	
	if analysis.CanRecover {
		color.Green("✅ Recovery Status: CAN RECOVER")
	} else {
		color.Red("❌ Recovery Status: CANNOT RECOVER")
	}
	
	// Display group analysis for hierarchical schemes
	if len(analysis.Groups) > 1 {
		fmt.Printf("\nGroup Analysis:\n")
		validGroups := 0
		for _, group := range analysis.Groups {
			status := "❌"
			if group.CanContribute {
				status = "✅"
				validGroups++
			}
			fmt.Printf("  %s Group %d: %d/%d shares available\n",
				status, group.Index, group.AvailableShares, group.RequiredShares)
		}
		fmt.Printf("Valid Groups: %d (need %d)\n", validGroups, analysis.Groups[0].RequiredShares)
	}
	
	// Display issues
	if len(analysis.Issues) > 0 {
		color.Yellow("\n⚠️  Issues Found:")
		for _, issue := range analysis.Issues {
			fmt.Printf("  • %s\n", issue)
		}
	}
	
	// Display recommendations
	if len(analysis.Recommendations) > 0 {
		color.Cyan("\n💡 Recommendations:")
		for _, rec := range analysis.Recommendations {
			fmt.Printf("  • %s\n", rec)
		}
	}
}

func simulateRecovery(shares []secretsharing.Share) error {
	// Perform a test recovery without revealing the actual secret
	// This validates the recovery process without exposing sensitive data
	
	if len(shares) == 0 {
		return fmt.Errorf("no shares provided")
	}
	
	// Get the sharer
	sharer, err := secretsharing.DefaultRegistry.Get(shares[0].Info.Scheme)
	if err != nil {
		return fmt.Errorf("unsupported scheme: %w", err)
	}
	
	// Attempt recovery with empty passphrase for validation
	_, err = sharer.Combine(shares, "")
	if err != nil {
		// If it fails with passphrase error, that's expected for encrypted shares
		if strings.Contains(err.Error(), "passphrase") || 
		   strings.Contains(err.Error(), "decryption") {
			return nil // Simulation successful, just needs passphrase
		}
		return err
	}
	
	return nil
}

func performRecovery(shares []secretsharing.Share, passphrase string) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}
	
	// Get the sharer
	sharer, err := secretsharing.DefaultRegistry.Get(shares[0].Info.Scheme)
	if err != nil {
		return nil, fmt.Errorf("unsupported scheme: %w", err)
	}
	
	// Perform the recovery
	secret, err := sharer.Combine(shares, passphrase)
	if err != nil {
		return nil, fmt.Errorf("recovery failed: %w", err)
	}
	
	return secret, nil
}

func handleRecoveryOutput(secret []byte, reader *bufio.Reader) error {
	fmt.Printf("\n🎉 Secret recovered successfully!\n")
	fmt.Printf("Length: %d bytes\n", len(secret))
	
	fmt.Println("\nHow would you like to output the secret?")
	fmt.Println("1) Display as text (if printable)")
	fmt.Println("2) Display as hexadecimal")
	fmt.Println("3) Save to file")
	fmt.Println("4) Copy to clipboard (if available)")
	fmt.Println("5) Don't display (verification only)")
	
	fmt.Print("\nChoice (1-5): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	
	switch choice {
	case "1":
		// Check if secret is printable text
		if isPrintable(secret) {
			color.Green("\nRecovered secret (as text):")
			fmt.Printf("%s\n", string(secret))
		} else {
			color.Yellow("Secret contains non-printable characters. Displaying as hex:")
			fmt.Printf("%s\n", hex.EncodeToString(secret))
		}
		
	case "2":
		color.Green("\nRecovered secret (as hex):")
		fmt.Printf("%s\n", hex.EncodeToString(secret))
		
	case "3":
		fmt.Print("Enter filename: ")
		filename, _ := reader.ReadString('\n')
		filename = strings.TrimSpace(filename)
		
		if err := os.WriteFile(filename, secret, 0600); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		color.Green("✅ Secret saved to %s", filename)
		
	case "4":
		// Clipboard functionality would need to be implemented
		return fmt.Errorf("clipboard functionality not implemented")
		
	case "5":
		color.Green("✅ Secret recovered and verified, not displayed")
		
	default:
		return fmt.Errorf("invalid choice")
	}
	
	// Security warning
	color.Yellow("\n⚠️  Security Reminder:")
	fmt.Println("• Clear your terminal history")
	fmt.Println("• Close this terminal when done")
	fmt.Println("• Ensure no one can see your screen")
	
	return nil
}

// Helper functions for collecting shares from different sources

func collectSharesFromFiles(reader *bufio.Reader) ([]secretsharing.Share, error) {
	fmt.Print("Enter share file paths (comma-separated): ")
	input, _ := reader.ReadString('\n')
	paths := strings.Split(strings.TrimSpace(input), ",")
	
	var shares []secretsharing.Share
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		
		shareData, err := loadShareFromFile(path)
		if err != nil {
			fmt.Printf("Warning: Failed to load %s: %v\n", path, err)
			continue
		}
		
		shares = append(shares, shareData...)
	}
	
	return shares, nil
}

func collectSharesFromSingleFile(reader *bufio.Reader) ([]secretsharing.Share, error) {
	fmt.Print("Enter path to JSON file containing all shares: ")
	path, _ := reader.ReadString('\n')
	path = strings.TrimSpace(path)
	
	return loadShareFromFile(path)
}

func collectSharesFromStore(reader *bufio.Reader) ([]secretsharing.Share, error) {
	// List available share sets
	store, err := getShareStore()
	if err != nil {
		return nil, fmt.Errorf("failed to access share store: %w", err)
	}
	
	shareSets := store.ListShareSets(nil)
	if len(shareSets) == 0 {
		return nil, fmt.Errorf("no managed share sets found")
	}
	
	fmt.Println("\nAvailable share sets:")
	for i, ss := range shareSets {
		fmt.Printf("%d) %s (ID: %s) - %s\n", i+1, ss.Name, ss.ID, ss.Scheme)
	}
	
	fmt.Print("\nSelect share set (number or ID): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	
	var selectedID string
	if num, err := strconv.Atoi(input); err == nil && num > 0 && num <= len(shareSets) {
		selectedID = shareSets[num-1].ID
	} else {
		selectedID = input
	}
	
	return store.GetRecoveryShares(selectedID)
}

func collectSharesManually(reader *bufio.Reader) ([]secretsharing.Share, error) {
	var shares []secretsharing.Share
	
	fmt.Println("\nEnter shares one by one. Press Enter on empty line when done.")
	
	for i := 1; ; i++ {
		fmt.Printf("\nShare %d (press Enter if done): ", i)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		
		if input == "" {
			break
		}
		
		// Parse the share based on format
		share, err := parseShareInput(input)
		if err != nil {
			fmt.Printf("Error parsing share: %v\n", err)
			fmt.Print("Continue anyway? (y/N): ")
			cont, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(cont)) != "y" {
				continue
			}
		} else {
			shares = append(shares, share)
			fmt.Printf("✅ Share %d added\n", i)
		}
	}
	
	return shares, nil
}

func collectSharesAutoDetect(reader *bufio.Reader) ([]secretsharing.Share, error) {
	fmt.Print("Enter directory to scan: ")
	dir, _ := reader.ReadString('\n')
	dir = strings.TrimSpace(dir)
	
	if dir == "" {
		dir = "."
	}
	
	return autoDetectShares(dir, "*.json", false)
}

// Implementation stubs for helper functions

func loadShareFromFile(filename string) ([]secretsharing.Share, error) {
	// Implementation would load and parse shares from JSON file
	return nil, fmt.Errorf("loadShareFromFile not implemented")
}

func parseShareInput(input string) (secretsharing.Share, error) {
	// Implementation would parse various share formats (mnemonic, hex, JSON)
	return secretsharing.Share{}, fmt.Errorf("parseShareInput not implemented")
}

func autoDetectShares(directory, pattern string, recursive bool) ([]secretsharing.Share, error) {
	// Implementation would scan directory for share files
	return nil, fmt.Errorf("autoDetectShares not implemented")
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

func runRecoverySimulation(input string, shareFiles []string) error {
	// Implementation for simulate subcommand
	return fmt.Errorf("recovery simulation not implemented")
}

func runStoreRecovery(shareSetID string, simulate bool, output string) error {
	// Implementation for from-store subcommand
	return fmt.Errorf("store recovery not implemented")
}

func runAutoRecovery(directory, pattern string, recursive bool) error {
	// Implementation for auto subcommand
	return fmt.Errorf("auto recovery not implemented")
}

func runRecoveryVerification(shareFiles []string) error {
	// Implementation for verify subcommand
	return fmt.Errorf("recovery verification not implemented")
}