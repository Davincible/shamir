package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/Davincible/shamir/internal/cli"
	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))
	slog.SetDefault(logger)

	rootCmd := &cobra.Command{
		Use:   "shamir",
		Short: "SLIP-0039 Shamir's Secret Sharing for secure backups",
		Long: `Shamir implements SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes.

This tool provides hierarchical secret sharing with encryption, compatible
with Trezor and other hardware wallets supporting SLIP-0039.

Features:
- SLIP-0039 standard implementation (default)
- Two-level hierarchical sharing (groups and members)
- Mnemonic encoding with custom wordlist
- Passphrase encryption with plausible deniability
- Hardware wallet compatibility (Trezor, etc.)
- BIP32/BIP44 key derivation support

For legacy non-standard shares, use 'shamir legacy' commands.`,
		Version: fmt.Sprintf("%s (built %s, commit %s)", Version, BuildTime, GitCommit),
	}

	rootCmd.AddCommand(
		cli.NewSplitCommandV2(),     // New SLIP-0039 split (default)
		cli.NewCombineCommandV2(),   // New SLIP-0039 combine (default)
		cli.NewVerifyCommand(),
		cli.NewDeriveCommand(),
		cli.NewGenerateCommand(),
		cli.NewLegacyCommand(),       // Old implementation under 'legacy'
	)

	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().BoolP("json", "j", false, "Output in JSON format")

	if err := rootCmd.Execute(); err != nil {
		slog.Error("Command execution failed", "error", err)
		os.Exit(1)
	}
}
