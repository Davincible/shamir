// Package slip039 implements SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes
// as specified at https://github.com/satoshilabs/slips/blob/master/slip-0039.md
//
// This implementation provides a hierarchical Shamir's Secret Sharing scheme
// with two-level sharing (groups and members), encryption, and mnemonic encoding.
package slip039

import (
	"crypto/rand"
	"fmt"
)

// DefaultIterationExponent is the default iteration exponent for PBKDF2
// This results in 10000 * 2^1 = 20000 iterations
const DefaultIterationExponent = 1

// MinMasterSecretLength is the minimum length of the master secret in bytes
const MinMasterSecretLength = 16 // 128 bits

// MaxMasterSecretLength is the maximum length of the master secret in bytes
const MaxMasterSecretLength = 32 // 256 bits

// MaxGroups is the maximum number of groups
const MaxGroups = 16

// MaxGroupMembers is the maximum number of members in a group
const MaxGroupMembers = 16

// SplitMasterSecret splits a master secret into SLIP-0039 mnemonic shares
func SplitMasterSecret(
	masterSecret []byte,
	passphrase string,
	groupThreshold byte,
	groups []GroupConfiguration,
) ([][]string, error) {
	// Use defaults
	iterationExponent := byte(DefaultIterationExponent)
	extendable := true // Default to extendable for flexibility
	
	// Generate shares
	shares, err := GenerateShares(
		groupThreshold,
		groups,
		masterSecret,
		passphrase,
		iterationExponent,
		extendable,
	)
	if err != nil {
		return nil, err
	}
	
	// Convert shares to mnemonics
	mnemonics := make([][]string, len(shares))
	for i, group := range shares {
		mnemonics[i] = make([]string, len(group))
		for j, share := range group {
			mnemonic, err := share.ToMnemonic()
			if err != nil {
				return nil, fmt.Errorf("failed to convert share to mnemonic: %w", err)
			}
			mnemonics[i][j] = mnemonic
		}
	}
	
	return mnemonics, nil
}

// RecoverMasterSecret recovers a master secret from SLIP-0039 mnemonic shares
func RecoverMasterSecret(mnemonics []string, passphrase string) ([]byte, error) {
	if len(mnemonics) == 0 {
		return nil, fmt.Errorf("no mnemonics provided")
	}
	
	// Convert mnemonics to shares
	shares := make([]Share, len(mnemonics))
	for i, mnemonic := range mnemonics {
		share, err := ShareFromMnemonic(mnemonic)
		if err != nil {
			return nil, fmt.Errorf("invalid mnemonic %d: %w", i+1, err)
		}
		shares[i] = *share
	}
	
	// Combine shares to recover master secret
	return CombineShares(shares, passphrase)
}

// ValidateMnemonic checks if a mnemonic is a valid SLIP-0039 share
func ValidateMnemonic(mnemonic string) error {
	_, err := ShareFromMnemonic(mnemonic)
	return err
}

// GetShareInfo extracts information from a SLIP-0039 mnemonic share
func GetShareInfo(mnemonic string) (*ShareInfo, error) {
	share, err := ShareFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	
	return &ShareInfo{
		Identifier:        share.CommonParameters.Identifier,
		Extendable:        share.CommonParameters.Extendable,
		IterationExponent: share.CommonParameters.IterationExponent,
		GroupIndex:        share.GroupIndex + 1, // Convert to 1-based for display
		GroupThreshold:    share.CommonParameters.GroupThreshold,
		GroupCount:        share.CommonParameters.GroupCount,
		MemberIndex:       share.MemberIndex + 1, // Convert to 1-based for display
		MemberThreshold:   share.MemberThreshold,
	}, nil
}

// ShareInfo contains human-readable information about a share
type ShareInfo struct {
	Identifier        uint16
	Extendable        bool
	IterationExponent byte
	GroupIndex        byte // 1-based for display
	GroupThreshold    byte
	GroupCount        byte
	MemberIndex       byte // 1-based for display
	MemberThreshold   byte
}

// String returns a human-readable representation of share info
func (si *ShareInfo) String() string {
	iterations := 10000 << si.IterationExponent
	return fmt.Sprintf(
		"Share ID: %04X\n"+
			"Extendable: %v\n"+
			"PBKDF2 Iterations: %d\n"+
			"Group: %d of %d (threshold %d)\n"+
			"Member: %d (threshold %d)",
		si.Identifier,
		si.Extendable,
		iterations,
		si.GroupIndex, si.GroupCount, si.GroupThreshold,
		si.MemberIndex, si.MemberThreshold,
	)
}

// GenerateMasterSecret generates a random master secret of the specified length
func GenerateMasterSecret(bytes int) ([]byte, error) {
	if bytes < MinMasterSecretLength || bytes > MaxMasterSecretLength {
		return nil, fmt.Errorf("master secret must be between %d and %d bytes",
			MinMasterSecretLength, MaxMasterSecretLength)
	}
	
	if bytes%2 != 0 {
		return nil, fmt.Errorf("master secret length must be even")
	}
	
	secret := make([]byte, bytes)
	if err := generateRandomBytes(secret); err != nil {
		return nil, err
	}
	
	return secret, nil
}

// generateRandomBytes fills the provided slice with random bytes
func generateRandomBytes(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// SimpleConfiguration creates a simple T-of-N sharing configuration
// This creates a single group with the specified threshold and member count
func SimpleConfiguration(threshold, count byte) []GroupConfiguration {
	return []GroupConfiguration{
		{
			MemberThreshold: threshold,
			MemberCount:     count,
		},
	}
}