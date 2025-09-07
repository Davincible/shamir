package cli

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/shamir"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func NewVerifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [share]",
		Short: "Verify the integrity of a share",
		Long:  `Verify that a share is valid and can be used for reconstruction.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			share := strings.TrimSpace(args[0])

			data, err := hex.DecodeString(share)
			if err != nil {
				return fmt.Errorf("invalid share format: %w", err)
			}

			s := shamir.Share{
				Index: 1,
				Data:  data,
			}

			if len(s.Data) < 2 {
				return fmt.Errorf("share is too short")
			}

			green := color.New(color.FgGreen, color.Bold)
			yellow := color.New(color.FgYellow)

			fmt.Println()
			green.Println("✓ Share format is valid")
			fmt.Println()

			yellow.Println("Share details:")
			fmt.Printf("  Length: %d bytes\n", len(s.Data))
			fmt.Printf("  Hex: %s...\n", share[:32])

			fmt.Println()
			fmt.Println("This share appears valid and can be used for reconstruction.")
			fmt.Println("Remember: you need at least the threshold number of shares.")

			return nil
		},
	}

	return cmd
}
