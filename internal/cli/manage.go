package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Davincible/shamir/pkg/sharestore"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// ManageCommand handles share management operations
func NewManageCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manage",
		Short: "Manage and organize your secret shares",
		Long: `Advanced share management system for organizing, tracking, and maintaining your secret shares.

Features:
• Store and organize share sets with metadata
• Track share distribution and status
• Verify share integrity and recoverability
• Search and filter share collections
• Import/export share sets
• Encrypted storage with passphrase protection

This command helps you maintain a comprehensive record of your shares
without storing the actual secrets unless explicitly requested.`,
		Example: `  # List all share sets
  shamir manage list

  # Add a new share set
  shamir manage add -i shares.json --name "Wallet Backup"

  # Search for specific shares
  shamir manage search "wallet"

  # Verify share integrity
  shamir manage verify abc123

  # Export share metadata
  shamir manage export abc123 -o backup.json`,
	}

	// Add subcommands
	cmd.AddCommand(
		newManageListCommand(),
		newManageAddCommand(),
		newManageShowCommand(),
		newManageSearchCommand(),
		newManageVerifyCommand(),
		newManageUpdateCommand(),
		newManageDeleteCommand(),
		newManageExportCommand(),
		newManageImportCommand(),
		newManageStatsCommand(),
	)

	return cmd
}

func newManageListCommand() *cobra.Command {
	var tags []string
	var format string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all share sets",
		Long:  "Display all stored share sets with their metadata and status information.",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getShareStore()
			if err != nil {
				return err
			}

			shareSets := store.ListShareSets(tags)

			switch format {
			case "json":
				return printJSON(shareSets)
			case "table":
				return printShareSetsTable(shareSets)
			default:
				return printShareSetsList(shareSets)
			}
		},
	}

	cmd.Flags().StringSliceVar(&tags, "tags", nil, "Filter by tags")
	cmd.Flags().StringVar(&format, "format", "list", "Output format (list, table, json)")

	return cmd
}

func newManageAddCommand() *cobra.Command {
	var (
		input       string
		name        string
		description string
		tags        []string
		storeShares bool
		encrypt     bool
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a share set to management",
		Long: `Add a new share set to the management system.

This command allows you to register share sets for tracking and management.
You can choose to store the actual share data (encrypted) or just metadata.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getShareStore()
			if err != nil {
				return err
			}

			if encrypt {
				fmt.Print("Enter encryption passphrase: ")
				passphrase, err := readPassword()
				if err != nil {
					return err
				}
				
				if err := store.EnableEncryption(string(passphrase)); err != nil {
					return fmt.Errorf("failed to enable encryption: %w", err)
				}
			}

			// Load shares from input
			shareSet, err := loadShareSetFromFile(input, name, description, tags, storeShares)
			if err != nil {
				return err
			}

			if err := store.AddShareSet(shareSet); err != nil {
				return fmt.Errorf("failed to add share set: %w", err)
			}

			color.Green("✅ Share set '%s' added successfully!", shareSet.Name)
			fmt.Printf("ID: %s\n", shareSet.ID)
			fmt.Printf("Shares: %d (threshold: %d)\n", shareSet.TotalShares, shareSet.Threshold)
			if len(shareSet.Groups) > 1 {
				fmt.Printf("Groups: %d\n", len(shareSet.Groups))
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "Input file containing shares")
	cmd.Flags().StringVar(&name, "name", "", "Name for the share set")
	cmd.Flags().StringVar(&description, "description", "", "Description")
	cmd.Flags().StringSliceVar(&tags, "tags", nil, "Tags for organization")
	cmd.Flags().BoolVar(&storeShares, "store-shares", false, "Store actual share data")
	cmd.Flags().BoolVar(&encrypt, "encrypt", false, "Encrypt stored data")

	cmd.MarkFlagRequired("input")

	return cmd
}

func newManageShowCommand() *cobra.Command {
	var showShares bool

	cmd := &cobra.Command{
		Use:   "show [ID]",
		Short: "Show detailed information about a share set",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getShareStore()
			if err != nil {
				return err
			}

			shareSet, err := store.GetShareSet(args[0])
			if err != nil {
				return err
			}

			return displayShareSetDetails(shareSet, showShares)
		},
	}

	cmd.Flags().BoolVar(&showShares, "show-shares", false, "Display actual share data (dangerous!)")

	return cmd
}

func newManageSearchCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search [QUERY]",
		Short: "Search share sets",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getShareStore()
			if err != nil {
				return err
			}

			results := store.SearchShareSets(args[0])

			if len(results) == 0 {
				fmt.Printf("No share sets found matching '%s'\n", args[0])
				return nil
			}

			color.Cyan("Found %d share set(s):\n", len(results))
			return printShareSetsList(results)
		},
	}

	return cmd
}

func newManageVerifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [ID]",
		Short: "Verify share integrity and recoverability",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getShareStore()
			if err != nil {
				return err
			}

			color.Yellow("🔍 Verifying share set %s...\n", args[0])

			report, err := store.VerifyShares(args[0])
			if err != nil {
				return err
			}

			return displayVerificationReport(report)
		},
	}

	return cmd
}

func newManageUpdateCommand() *cobra.Command {
	var (
		name        string
		description string
		addTags     []string
		removeTags  []string
		status      string
		shareIndex  int
	)

	cmd := &cobra.Command{
		Use:   "update [ID]",
		Short: "Update share set metadata or share status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getShareStore()
			if err != nil {
				return err
			}

			shareSetID := args[0]

			// Update share status if specified
			if status != "" && shareIndex > 0 {
				shareStatus := sharestore.ShareStatus(status)
				if err := store.UpdateShareStatus(shareSetID, shareIndex, shareStatus); err != nil {
					return err
				}
				color.Green("✅ Updated share #%d status to '%s'", shareIndex, status)
				return nil
			}

			// Update metadata
			shareSet, err := store.GetShareSet(shareSetID)
			if err != nil {
				return err
			}

			if name != "" {
				shareSet.Name = name
			}

			if description != "" {
				shareSet.Description = description
			}

			// Add tags
			if len(addTags) > 0 {
				tagSet := make(map[string]bool)
				for _, tag := range shareSet.Tags {
					tagSet[tag] = true
				}
				for _, tag := range addTags {
					tagSet[tag] = true
				}
				
				shareSet.Tags = make([]string, 0, len(tagSet))
				for tag := range tagSet {
					shareSet.Tags = append(shareSet.Tags, tag)
				}
			}

			// Remove tags
			if len(removeTags) > 0 {
				removeSet := make(map[string]bool)
				for _, tag := range removeTags {
					removeSet[tag] = true
				}
				
				var newTags []string
				for _, tag := range shareSet.Tags {
					if !removeSet[tag] {
						newTags = append(newTags, tag)
					}
				}
				shareSet.Tags = newTags
			}

			shareSet.Modified = time.Now()

			if err := store.AddShareSet(shareSet); err != nil {
				return fmt.Errorf("failed to update share set: %w", err)
			}

			color.Green("✅ Share set updated successfully!")
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Update name")
	cmd.Flags().StringVar(&description, "description", "", "Update description")
	cmd.Flags().StringSliceVar(&addTags, "add-tags", nil, "Add tags")
	cmd.Flags().StringSliceVar(&removeTags, "remove-tags", nil, "Remove tags")
	cmd.Flags().StringVar(&status, "status", "", "Update share status (available, missing, corrupted, distributed)")
	cmd.Flags().IntVar(&shareIndex, "share-index", 0, "Share index for status update")

	return cmd
}

func newManageDeleteCommand() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete [ID]",
		Short: "Delete a share set from management",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getShareStore()
			if err != nil {
				return err
			}

			shareSetID := args[0]

			// Get share set info for confirmation
			shareSet, err := store.GetShareSet(shareSetID)
			if err != nil {
				return err
			}

			// Confirmation
			if !force {
				fmt.Printf("This will delete share set '%s' from management.\n", shareSet.Name)
				fmt.Printf("ID: %s\n", shareSet.ID)
				fmt.Print("Are you sure? (y/N): ")
				
				var response string
				fmt.Scanln(&response)
				
				if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
					fmt.Println("Deletion cancelled.")
					return nil
				}
			}

			if err := store.DeleteShareSet(shareSetID); err != nil {
				return fmt.Errorf("failed to delete share set: %w", err)
			}

			color.Green("✅ Share set deleted from management")
			color.Yellow("⚠️  This only removes the management record, not the actual shares")
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation")

	return cmd
}

func newManageExportCommand() *cobra.Command {
	var (
		output        string
		includeShares bool
		format        string
	)

	cmd := &cobra.Command{
		Use:   "export [ID]",
		Short: "Export share set for backup or transfer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getShareStore()
			if err != nil {
				return err
			}

			exportData, err := store.ExportShareSet(args[0], includeShares)
			if err != nil {
				return err
			}

			var data []byte
			switch format {
			case "json":
				data, err = json.MarshalIndent(exportData, "", "  ")
			default:
				return fmt.Errorf("unsupported format: %s", format)
			}

			if err != nil {
				return fmt.Errorf("failed to marshal export data: %w", err)
			}

			if output != "" {
				if err := os.WriteFile(output, data, 0600); err != nil {
					return fmt.Errorf("failed to write export file: %w", err)
				}
				color.Green("✅ Share set exported to %s", output)
			} else {
				fmt.Print(string(data))
			}

			if includeShares {
				color.Yellow("⚠️  Export includes actual share data - keep secure!")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file")
	cmd.Flags().BoolVar(&includeShares, "include-shares", false, "Include actual share data")
	cmd.Flags().StringVar(&format, "format", "json", "Export format")

	return cmd
}

func newManageImportCommand() *cobra.Command {
	var (
		input     string
		overwrite bool
	)

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import share set from export data",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getShareStore()
			if err != nil {
				return err
			}

			data, err := os.ReadFile(input)
			if err != nil {
				return fmt.Errorf("failed to read input file: %w", err)
			}

			var exportData sharestore.ExportData
			if err := json.Unmarshal(data, &exportData); err != nil {
				return fmt.Errorf("failed to parse export data: %w", err)
			}

			if err := store.ImportShareSet(&exportData, overwrite); err != nil {
				return fmt.Errorf("failed to import share set: %w", err)
			}

			color.Green("✅ Share set '%s' imported successfully!", exportData.ShareSet.Name)
			fmt.Printf("ID: %s\n", exportData.ShareSet.ID)

			return nil
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "Import file")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing share set")

	cmd.MarkFlagRequired("input")

	return cmd
}

func newManageStatsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show statistics about managed share sets",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getShareStore()
			if err != nil {
				return err
			}

			return displayStats(store)
		},
	}

	return cmd
}

// Helper functions

func getShareStore() (*sharestore.ShareStore, error) {
	storePath := getShareStorePath()
	return sharestore.NewShareStore(storePath)
}

func getShareStorePath() string {
	if path := os.Getenv("SHAMIR_STORE_PATH"); path != "" {
		return path
	}
	
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./shamir_store"
	}
	
	return homeDir + "/.shamir/store"
}

func loadShareSetFromFile(filename, name, description string, tags []string, storeShares bool) (*sharestore.ShareSet, error) {
	// This would load shares from a JSON file and create a ShareSet
	// Implementation depends on the exact file format
	return nil, fmt.Errorf("loadShareSetFromFile not implemented")
}

func printShareSetsList(shareSets []*sharestore.ShareSet) error {
	if len(shareSets) == 0 {
		fmt.Println("No share sets found.")
		return nil
	}

	for i, ss := range shareSets {
		if i > 0 {
			fmt.Println()
		}

		// Header with ID and name
		color.Cyan("📁 %s", ss.Name)
		fmt.Printf("   ID: %s\n", ss.ID)
		
		// Basic info
		fmt.Printf("   Scheme: %s | Threshold: %d/%d", 
			ss.Scheme, ss.Threshold, ss.TotalShares)
		
		if len(ss.Groups) > 1 {
			fmt.Printf(" | Groups: %d", len(ss.Groups))
		}
		fmt.Println()
		
		// Status and dates
		fmt.Printf("   Created: %s", ss.Created.Format("2006-01-02 15:04"))
		if !ss.Modified.Equal(ss.Created) {
			fmt.Printf(" | Modified: %s", ss.Modified.Format("2006-01-02 15:04"))
		}
		fmt.Println()
		
		// Tags
		if len(ss.Tags) > 0 {
			fmt.Printf("   Tags: %s\n", strings.Join(ss.Tags, ", "))
		}
		
		// Description
		if ss.Description != "" {
			fmt.Printf("   %s\n", ss.Description)
		}
		
		// Share status summary
		available := 0
		for _, share := range ss.Shares {
			if share.Status == sharestore.ShareStatusAvailable {
				available++
			}
		}
		
		if available >= ss.Threshold {
			color.Green("   Status: ✅ Recoverable (%d/%d available)", available, ss.TotalShares)
		} else {
			color.Red("   Status: ❌ Not recoverable (%d/%d available)", available, ss.TotalShares)
		}
	}

	return nil
}

func printShareSetsTable(shareSets []*sharestore.ShareSet) error {
	// Implementation for table format
	return fmt.Errorf("table format not implemented")
}

func displayShareSetDetails(shareSet *sharestore.ShareSet, showShares bool) error {
	fmt.Printf("Share Set Details\n")
	fmt.Printf("=================\n\n")
	
	fmt.Printf("Name: %s\n", shareSet.Name)
	fmt.Printf("ID: %s\n", shareSet.ID)
	fmt.Printf("Scheme: %s\n", shareSet.Scheme)
	fmt.Printf("Threshold: %d of %d shares\n", shareSet.Threshold, shareSet.TotalShares)
	
	if shareSet.Description != "" {
		fmt.Printf("Description: %s\n", shareSet.Description)
	}
	
	fmt.Printf("Created: %s\n", shareSet.Created.Format("2006-01-02 15:04:05"))
	if !shareSet.Modified.Equal(shareSet.Created) {
		fmt.Printf("Modified: %s\n", shareSet.Modified.Format("2006-01-02 15:04:05"))
	}
	
	if len(shareSet.Tags) > 0 {
		fmt.Printf("Tags: %s\n", strings.Join(shareSet.Tags, ", "))
	}
	
	// Groups information
	if len(shareSet.Groups) > 1 {
		fmt.Printf("\nGroups (%d):\n", len(shareSet.Groups))
		for _, group := range shareSet.Groups {
			fmt.Printf("  Group %d: %d of %d", group.Index, group.Threshold, group.Count)
			if group.Name != "" {
				fmt.Printf(" (%s)", group.Name)
			}
			fmt.Printf(" - Members: %v\n", group.Members)
		}
	}
	
	// Shares information
	fmt.Printf("\nShares (%d):\n", len(shareSet.Shares))
	for _, share := range shareSet.Shares {
		statusIcon := "❓"
		switch share.Status {
		case sharestore.ShareStatusAvailable:
			statusIcon = "✅"
		case sharestore.ShareStatusMissing:
			statusIcon = "❌"
		case sharestore.ShareStatusCorrupted:
			statusIcon = "⚠️"
		case sharestore.ShareStatusDistributed:
			statusIcon = "📤"
		}
		
		fmt.Printf("  %s Share #%d", statusIcon, share.Index)
		if share.Name != "" {
			fmt.Printf(" (%s)", share.Name)
		}
		fmt.Printf(" - %s", share.Status)
		
		if share.Location != "" {
			fmt.Printf(" @ %s", share.Location)
		}
		
		if share.LastVerified != nil {
			fmt.Printf(" | Verified: %s", share.LastVerified.Format("2006-01-02"))
		}
		fmt.Println()
		
		if share.Notes != "" {
			fmt.Printf("    Notes: %s\n", share.Notes)
		}
		
		if showShares && share.Share != nil {
			color.Red("    ⚠️  SENSITIVE DATA BELOW ⚠️")
			if share.Share.Mnemonic != "" {
				fmt.Printf("    Mnemonic: %s\n", share.Share.Mnemonic)
			} else {
				fmt.Printf("    Data: %x\n", share.Share.Data)
			}
		}
	}
	
	return nil
}

func displayVerificationReport(report *sharestore.VerificationReport) error {
	fmt.Printf("Verification Report\n")
	fmt.Printf("==================\n\n")
	
	fmt.Printf("Share Set: %s\n", report.ShareSetID)
	fmt.Printf("Timestamp: %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Total Shares: %d\n", report.TotalShares)
	fmt.Printf("Valid Shares: %d\n", report.ValidShares)
	
	if report.IsRecoverable {
		color.Green("Status: ✅ Secret is recoverable")
	} else {
		color.Red("Status: ❌ Secret is NOT recoverable")
	}
	
	fmt.Printf("\nDetailed Results:\n")
	for _, result := range report.Results {
		statusIcon := "❓"
		if result.IsValid {
			statusIcon = "✅"
		} else if result.Error != "" {
			statusIcon = "❌"
		}
		
		fmt.Printf("  %s Share #%d: %s", statusIcon, result.ShareIndex, result.Status)
		if result.Error != "" {
			fmt.Printf(" (%s)", result.Error)
		}
		fmt.Println()
	}
	
	return nil
}

func displayStats(store *sharestore.ShareStore) error {
	shareSets := store.ListShareSets(nil)
	
	fmt.Printf("Share Management Statistics\n")
	fmt.Printf("===========================\n\n")
	
	fmt.Printf("Total Share Sets: %d\n", len(shareSets))
	
	// Count by scheme
	schemeCount := make(map[string]int)
	totalShares := 0
	recoverableSets := 0
	
	for _, ss := range shareSets {
		schemeCount[string(ss.Scheme)]++
		totalShares += ss.TotalShares
		
		// Check if recoverable
		available := 0
		for _, share := range ss.Shares {
			if share.Status == sharestore.ShareStatusAvailable {
				available++
			}
		}
		if available >= ss.Threshold {
			recoverableSets++
		}
	}
	
	fmt.Printf("Total Shares: %d\n", totalShares)
	fmt.Printf("Recoverable Sets: %d (%.1f%%)\n", 
		recoverableSets, float64(recoverableSets*100)/float64(len(shareSets)))
	
	fmt.Printf("\nBy Scheme:\n")
	for scheme, count := range schemeCount {
		fmt.Printf("  %s: %d\n", scheme, count)
	}
	
	return nil
}

func printJSON(data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonData))
	return nil
}

func readPassword() ([]byte, error) {
	// This would read a password from stdin
	// Implementation depends on terminal handling
	return nil, fmt.Errorf("password reading not implemented")
}