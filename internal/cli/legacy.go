package cli

import (
	"github.com/spf13/cobra"
	"github.com/fatih/color"
	"fmt"
)

// NewLegacyCommand creates a command group for legacy operations
func NewLegacyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "legacy",
		Short: "Legacy Shamir operations (non-standard)",
		Long: `Legacy Shamir's Secret Sharing operations using the old implementation.

⚠️  WARNING: These commands use a non-standard implementation that is:
- NOT compatible with SLIP-0039
- NOT compatible with hardware wallets
- NOT interoperable with other implementations

Use these commands only to recover old shares. For new operations,
use the standard 'split' and 'combine' commands which use SLIP-0039.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			yellow := color.New(color.FgYellow, color.Bold)
			yellow.Println("⚠️  Using legacy non-standard Shamir implementation")
			fmt.Println()
		},
	}

	// Add the old split and combine commands as subcommands
	cmd.AddCommand(
		NewSplitCommand(),    // The old split command
		NewCombineCommand(),  // The old combine command
	)

	return cmd
}