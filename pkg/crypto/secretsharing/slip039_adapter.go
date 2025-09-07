// SLIP-0039 adapter for the unified secret sharing interface
package secretsharing

import (
	"fmt"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/slip039"
)

// SLIP039Sharer implements SecretSharer interface for SLIP-0039
type SLIP039Sharer struct{}

// NewSLIP039Sharer creates a new SLIP-0039 sharer
func NewSLIP039Sharer() *SLIP039Sharer {
	return &SLIP039Sharer{}
}

// Split implements the SecretSharer interface for SLIP-0039
func (s *SLIP039Sharer) Split(secret []byte, config SecretSharingConfig) ([]Share, error) {
	// Validate configuration
	if err := s.ValidateConfig(config); err != nil {
		return nil, err
	}

	// Convert our config to SLIP-0039 format
	slip039Groups := make([]slip039.GroupConfiguration, len(config.Groups))
	for i, group := range config.Groups {
		slip039Groups[i] = slip039.GroupConfiguration{
			MemberThreshold: byte(group.MemberThreshold),
			MemberCount:     byte(group.MemberCount),
		}
	}

	// Generate SLIP-0039 shares
	mnemonics, err := slip039.SplitMasterSecret(
		secret,
		config.Passphrase,
		byte(config.GroupThreshold),
		slip039Groups,
	)
	if err != nil {
		return nil, fmt.Errorf("SLIP-0039 split failed: %w", err)
	}

	// Convert to unified Share format
	var shares []Share
	identifier := ""
	
	for groupIndex, group := range mnemonics {
		for memberIndex, mnemonic := range group {
			// Extract share info from the mnemonic
			slip039Share, err := slip039.ShareFromMnemonic(mnemonic)
			if err != nil {
				return nil, fmt.Errorf("failed to parse generated mnemonic: %w", err)
			}
			
			// Set identifier from first share
			if identifier == "" {
				identifier = fmt.Sprintf("%04X", slip039Share.CommonParameters.Identifier)
			}

			share := Share{
				Info: ShareInfo{
					Scheme:          SchemeSLIP039,
					Identifier:      identifier,
					GroupIndex:      groupIndex + 1, // 1-based for display
					GroupThreshold:  config.GroupThreshold,
					GroupCount:      len(config.Groups),
					MemberIndex:     memberIndex + 1, // 1-based for display
					MemberThreshold: config.Groups[groupIndex].MemberThreshold,
					IsVerifiable:    false, // SLIP-0039 is not publicly verifiable
				},
				Data:     slip039Share.ShareValue,
				Mnemonic: mnemonic,
			}
			
			shares = append(shares, share)
		}
	}

	return shares, nil
}

// Combine implements the SecretSharer interface for SLIP-0039
func (s *SLIP039Sharer) Combine(shares []Share, passphrase string) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	// Extract mnemonics from shares
	mnemonics := make([]string, len(shares))
	for i, share := range shares {
		if share.Info.Scheme != SchemeSLIP039 {
			return nil, fmt.Errorf("share %d is not SLIP-0039", i)
		}
		mnemonics[i] = share.Mnemonic
	}

	// Use SLIP-0039 recovery
	secret, err := slip039.RecoverMasterSecret(mnemonics, passphrase)
	if err != nil {
		return nil, fmt.Errorf("SLIP-0039 recovery failed: %w", err)
	}

	return secret, nil
}

// Verify implements the SecretSharer interface for SLIP-0039
func (s *SLIP039Sharer) Verify(share Share) error {
	if share.Info.Scheme != SchemeSLIP039 {
		return fmt.Errorf("share is not SLIP-0039")
	}

	if share.Mnemonic == "" {
		return fmt.Errorf("SLIP-0039 share missing mnemonic")
	}

	// Use SLIP-0039's built-in validation
	return slip039.ValidateMnemonic(share.Mnemonic)
}

// GetShareInfo implements the SecretSharer interface for SLIP-0039
func (s *SLIP039Sharer) GetShareInfo(share Share) ShareInfo {
	return share.Info
}

// ValidateConfig implements the SecretSharer interface for SLIP-0039
func (s *SLIP039Sharer) ValidateConfig(config SecretSharingConfig) error {
	if config.Scheme != SchemeSLIP039 {
		return fmt.Errorf("config is not for SLIP-0039")
	}

	if len(config.Groups) == 0 {
		return fmt.Errorf("at least one group is required")
	}

	if len(config.Groups) > 16 {
		return fmt.Errorf("maximum 16 groups allowed, got %d", len(config.Groups))
	}

	if config.GroupThreshold <= 0 || config.GroupThreshold > len(config.Groups) {
		return fmt.Errorf("group threshold must be between 1 and %d", len(config.Groups))
	}

	for i, group := range config.Groups {
		if group.MemberCount == 0 {
			return fmt.Errorf("group %d: member count must be at least 1", i)
		}

		if group.MemberCount > 16 {
			return fmt.Errorf("group %d: maximum 16 members allowed, got %d", i, group.MemberCount)
		}

		if group.MemberThreshold == 0 {
			return fmt.Errorf("group %d: member threshold must be at least 1", i)
		}

		if group.MemberThreshold > group.MemberCount {
			return fmt.Errorf("group %d: threshold %d cannot exceed count %d",
				i, group.MemberThreshold, group.MemberCount)
		}

		// SLIP-0039 recommendation: if threshold is 1, count should also be 1
		if group.MemberThreshold == 1 && group.MemberCount > 1 {
			return fmt.Errorf("group %d: when threshold is 1, count should also be 1 (SLIP-0039 recommendation)", i)
		}
	}

	return nil
}

// GetScheme implements the SecretSharer interface for SLIP-0039
func (s *SLIP039Sharer) GetScheme() SchemeType {
	return SchemeSLIP039
}

// ShareFromMnemonic creates a Share from a SLIP-0039 mnemonic string
func (s *SLIP039Sharer) ShareFromMnemonic(mnemonic string) (Share, error) {
	// Validate and parse the mnemonic
	slip039Share, err := slip039.ShareFromMnemonic(mnemonic)
	if err != nil {
		return Share{}, fmt.Errorf("invalid SLIP-0039 mnemonic: %w", err)
	}

	// Convert to unified format
	share := Share{
		Info: ShareInfo{
			Scheme:          SchemeSLIP039,
			Identifier:      fmt.Sprintf("%04X", slip039Share.CommonParameters.Identifier),
			GroupIndex:      int(slip039Share.GroupIndex) + 1, // 1-based
			GroupThreshold:  int(slip039Share.CommonParameters.GroupThreshold),
			GroupCount:      int(slip039Share.CommonParameters.GroupCount),
			MemberIndex:     int(slip039Share.MemberIndex) + 1, // 1-based
			MemberThreshold: int(slip039Share.MemberThreshold),
			IsVerifiable:    false,
		},
		Data:     slip039Share.ShareValue,
		Mnemonic: mnemonic,
	}

	return share, nil
}

// MnemonicsFromShares extracts mnemonic strings from shares
func (s *SLIP039Sharer) MnemonicsFromShares(shares []Share) []string {
	mnemonics := make([]string, len(shares))
	for i, share := range shares {
		mnemonics[i] = share.Mnemonic
	}
	return mnemonics
}

// DetectSLIP039 attempts to detect if a string is a SLIP-0039 mnemonic
func DetectSLIP039(input string) bool {
	// Basic heuristic: SLIP-0039 shares are typically 20 or 33 words
	words := strings.Fields(strings.TrimSpace(input))
	if len(words) != 20 && len(words) != 33 {
		return false
	}
	
	// Try to validate as SLIP-0039
	return slip039.ValidateMnemonic(input) == nil
}

// init registers the SLIP-0039 sharer with the default registry
func init() {
	DefaultRegistry.Register(SchemeSLIP039, NewSLIP039Sharer())
}