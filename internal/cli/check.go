package cli

import (
	"fmt"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/slip039"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// NewCheckCommand creates a command to check share compatibility
func NewCheckCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check if shares are compatible for recovery",
		Long: `Analyzes multiple SLIP-0039 shares to determine if they can be
combined for recovery. Shows what's needed for successful recovery.`,
		Example: `  # Check shares interactively
  shamir check

  # Check specific shares
  shamir check "share1..." "share2..."`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return checkShares(args)
		},
	}

	return cmd
}

func checkShares(args []string) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)
	red := color.New(color.FgRed, color.Bold)

	var shares []string

	// Get shares from args or interactively
	if len(args) > 0 {
		shares = args
	} else {
		fmt.Println()
		cyan.Println("SHARE COMPATIBILITY CHECKER")
		fmt.Println("=" + strings.Repeat("=", 40))
		fmt.Println()
		fmt.Println("Enter shares to check (press Enter twice when done):")
		fmt.Println()

		for {
			fmt.Printf("Share %d: ", len(shares)+1)
			var share string
			fmt.Scanln(&share)
			
			if share == "" {
				if len(shares) >= 2 {
					break
				}
				if len(shares) > 0 {
					fmt.Println("Enter at least 2 shares to check compatibility")
				}
				continue
			}

			shares = append(shares, share)
		}
	}

	if len(shares) < 2 {
		return fmt.Errorf("need at least 2 shares to check compatibility")
	}

	fmt.Println()
	cyan.Printf("Analyzing %d shares...\n", len(shares))
	fmt.Println()

	// Validate each share and collect info
	type ShareDetails struct {
		Info  *slip039.ShareInfo
		Valid bool
		Error error
	}

	details := make([]ShareDetails, len(shares))
	var firstIdentifier uint16
	identifierMismatch := false

	for i, share := range shares {
		if err := slip039.ValidateMnemonic(share); err != nil {
			details[i] = ShareDetails{Valid: false, Error: err}
			red.Printf("Share %d: ❌ Invalid - %v\n", i+1, err)
			continue
		}

		info, err := slip039.GetShareInfo(share)
		if err != nil {
			details[i] = ShareDetails{Valid: false, Error: err}
			red.Printf("Share %d: ❌ Error - %v\n", i+1, err)
			continue
		}

		details[i] = ShareDetails{Info: info, Valid: true}
		
		if i == 0 {
			firstIdentifier = info.Identifier
		} else if info.Identifier != firstIdentifier {
			identifierMismatch = true
		}

		green.Printf("Share %d: ✓ Valid\n", i+1)
		fmt.Printf("  Group: %d of %d (threshold: %d)\n", 
			info.GroupIndex, info.GroupCount, info.GroupThreshold)
		fmt.Printf("  Member: %d (threshold: %d)\n", 
			info.MemberIndex, info.MemberThreshold)
	}

	fmt.Println()

	// Check compatibility
	if identifierMismatch {
		red.Println("❌ INCOMPATIBLE SHARES")
		fmt.Println("These shares are from different secrets and cannot be combined.")
		return nil
	}

	// Analyze what we have
	validShares := 0
	groupMap := make(map[int][]int) // group index -> member indices

	for _, d := range details {
		if d.Valid && d.Info != nil {
			validShares++
			groupIdx := int(d.Info.GroupIndex)
			memberIdx := int(d.Info.MemberIndex)
			groupMap[groupIdx] = append(groupMap[groupIdx], memberIdx)
		}
	}

	if validShares == 0 {
		red.Println("❌ No valid shares found")
		return nil
	}

	// Get requirements from first valid share
	var requirements *slip039.ShareInfo
	for _, d := range details {
		if d.Valid && d.Info != nil {
			requirements = d.Info
			break
		}
	}

	yellow.Println("📊 RECOVERY REQUIREMENTS:")
	fmt.Println()
	
	if requirements.GroupCount == 1 {
		// Simple mode
		fmt.Printf("Need: %d of %d shares\n", requirements.MemberThreshold, requirements.GroupCount)
		fmt.Printf("Have: %d valid shares\n", validShares)
		
		if validShares >= int(requirements.MemberThreshold) {
			green.Println("\n✅ SUFFICIENT SHARES FOR RECOVERY!")
			fmt.Println("You can recover the secret with these shares.")
		} else {
			needed := int(requirements.MemberThreshold) - validShares
			red.Printf("\n❌ INSUFFICIENT SHARES\n")
			fmt.Printf("Need %d more share(s) for recovery.\n", needed)
		}
	} else {
		// Group mode
		fmt.Printf("Groups: %d total, need %d\n", 
			requirements.GroupCount, requirements.GroupThreshold)
		
		// Check each group
		sufficientGroups := 0
		fmt.Println("\nGroup Status:")
		for groupIdx := 1; groupIdx <= int(requirements.GroupCount); groupIdx++ {
			members := groupMap[groupIdx]
			
			// Assume all groups have same threshold as first group (simplification)
			threshold := requirements.MemberThreshold
			
			if len(members) > 0 {
				if len(members) >= int(threshold) {
					green.Printf("  Group %d: ✓ Sufficient (%d of %d members)\n",
						groupIdx, len(members), threshold)
					sufficientGroups++
				} else {
					yellow.Printf("  Group %d: ⚠ Partial (%d of %d members)\n",
						groupIdx, len(members), threshold)
				}
			} else {
				fmt.Printf("  Group %d: No shares\n", groupIdx)
			}
		}
		
		fmt.Println()
		if sufficientGroups >= int(requirements.GroupThreshold) {
			green.Println("✅ SUFFICIENT SHARES FOR RECOVERY!")
			fmt.Printf("Have %d complete groups (need %d).\n", 
				sufficientGroups, requirements.GroupThreshold)
		} else {
			red.Println("❌ INSUFFICIENT SHARES")
			fmt.Printf("Have %d complete groups, need %d.\n",
				sufficientGroups, requirements.GroupThreshold)
			
			// Suggest what's needed
			fmt.Println("\nTo recover, you need:")
			for groupIdx := 1; groupIdx <= int(requirements.GroupCount); groupIdx++ {
				members := groupMap[groupIdx]
				threshold := requirements.MemberThreshold
				
				if len(members) < int(threshold) {
					needed := int(threshold) - len(members)
					if needed > 0 {
						fmt.Printf("  - %d more share(s) from Group %d\n", needed, groupIdx)
					}
				}
			}
		}
	}

	// Additional info
	if requirements.Extendable {
		fmt.Println()
		cyan.Println("ℹ️  These shares use extendable backup (passphrase required)")
	}

	return nil
}