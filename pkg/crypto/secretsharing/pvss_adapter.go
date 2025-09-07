// PVSS adapter for the unified secret sharing interface
package secretsharing

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Davincible/shamir/pkg/crypto/pvss"
)

// PVSSSharer implements SecretSharer interface for PVSS
type PVSSSharer struct {
	defaultCurve pvss.CurveType
}

// NewPVSSSharer creates a new PVSS sharer
func NewPVSSSharer() *PVSSSharer {
	return &PVSSSharer{
		defaultCurve: pvss.CurveP256, // Default to P-256
	}
}

// Split implements the SecretSharer interface for PVSS
func (p *PVSSSharer) Split(secret []byte, config SecretSharingConfig) ([]Share, error) {
	// Validate configuration
	if err := p.ValidateConfig(config); err != nil {
		return nil, err
	}

	// PVSS currently supports single-level sharing only
	if len(config.Groups) != 1 {
		return nil, fmt.Errorf("PVSS currently supports single-level sharing only (got %d groups)", len(config.Groups))
	}

	group := config.Groups[0]
	
	// Determine curve type
	curveType := pvss.CurveP256
	if config.CurveType != "" {
		curveType = pvss.CurveType(config.CurveType)
	}

	// Create PVSS system
	pvssSystem, err := pvss.NewPVSSSystem(curveType, group.MemberThreshold, group.MemberCount)
	if err != nil {
		return nil, fmt.Errorf("failed to create PVSS system: %w", err)
	}

	// For larger secrets, we need to hash them down to fit in the field
	processedSecret := p.processSecret(secret)

	// Generate PVSS shares
	pvssShares, err := pvssSystem.GenerateShares(processedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PVSS shares: %w", err)
	}

	// Generate identifier from hash of the first commitment
	identifier := p.generateIdentifier(pvssShares[0])

	// Convert to unified Share format
	shares := make([]Share, len(pvssShares))
	for i, pvssShare := range pvssShares {
		// Serialize PVSS-specific data
		commitmentData, err := json.Marshal(pvssShare.Commitment)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize commitment: %w", err)
		}

		shareData, err := json.Marshal(pvssShare)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PVSS share: %w", err)
		}

		shares[i] = Share{
			Info: ShareInfo{
				Scheme:          SchemePVSS,
				Identifier:      identifier,
				GroupIndex:      1, // Single group for PVSS
				GroupThreshold:  1, // Single group
				GroupCount:      1,
				MemberIndex:     pvssShare.Index,
				MemberThreshold: group.MemberThreshold,
				IsVerifiable:    true, // PVSS is publicly verifiable
			},
			Data:       shareData,
			Commitment: commitmentData,
			// Note: PVSS doesn't use traditional mnemonic words
			// We could extend this to encode PVSS shares as words in the future
		}
	}

	return shares, nil
}

// processSecret processes the secret to fit within the elliptic curve field
func (p *PVSSSharer) processSecret(secret []byte) []byte {
	// For secrets larger than 32 bytes, hash them down
	if len(secret) > 32 {
		hash := sha256.Sum256(secret)
		return hash[:]
	}
	
	// For smaller secrets, pad with zeros if needed
	if len(secret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(secret):], secret)
		return padded
	}
	
	return secret
}

// generateIdentifier generates a unique identifier for the share set
func (p *PVSSSharer) generateIdentifier(pvssShare *pvss.PVSSShare) string {
	// Use hash of the first commitment point as identifier
	if len(pvssShare.Commitment.Commitments) > 0 {
		first := pvssShare.Commitment.Commitments[0]
		data := append(first.X.Bytes(), first.Y.Bytes()...)
		hash := sha256.Sum256(data)
		return fmt.Sprintf("%08X", hash[:4])
	}
	return "00000000"
}

// Combine implements the SecretSharer interface for PVSS
func (p *PVSSSharer) Combine(shares []Share, passphrase string) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	// Validate all shares are PVSS
	for i, share := range shares {
		if share.Info.Scheme != SchemePVSS {
			return nil, fmt.Errorf("share %d is not PVSS", i)
		}
	}

	// Deserialize PVSS shares
	pvssShares := make([]*pvss.PVSSShare, len(shares))
	var pvssSystem *pvss.PVSSSystem

	for i, share := range shares {
		var pvssShare pvss.PVSSShare
		if err := json.Unmarshal(share.Data, &pvssShare); err != nil {
			return nil, fmt.Errorf("failed to deserialize PVSS share %d: %w", i, err)
		}
		pvssShares[i] = &pvssShare

		// Create PVSS system from first share (all should have same parameters)
		if i == 0 {
			threshold := share.Info.MemberThreshold
			numShares := len(shares) // This might not be total, but sufficient for reconstruction
			
			// Try to determine curve type from share data
			curveType := pvss.CurveP256 // Default
			
			var err error
			pvssSystem, err = pvss.NewPVSSSystem(curveType, threshold, numShares)
			if err != nil {
				return nil, fmt.Errorf("failed to create PVSS system for recovery: %w", err)
			}
		}
	}

	// Recover the secret using PVSS
	secret, err := pvssSystem.RecoverSecret(pvssShares)
	if err != nil {
		return nil, fmt.Errorf("PVSS recovery failed: %w", err)
	}

	return secret, nil
}

// Verify implements the SecretSharer interface for PVSS
func (p *PVSSSharer) Verify(share Share) error {
	if share.Info.Scheme != SchemePVSS {
		return fmt.Errorf("share is not PVSS")
	}

	if len(share.Data) == 0 {
		return fmt.Errorf("PVSS share missing data")
	}

	// Deserialize PVSS share
	var pvssShare pvss.PVSSShare
	if err := json.Unmarshal(share.Data, &pvssShare); err != nil {
		return fmt.Errorf("failed to deserialize PVSS share: %w", err)
	}

	// Create PVSS system for verification
	curveType := pvss.CurveP256 // Default, could be extracted from share metadata
	pvssSystem, err := pvss.NewPVSSSystem(curveType, share.Info.MemberThreshold, 1)
	if err != nil {
		return fmt.Errorf("failed to create PVSS system for verification: %w", err)
	}

	// Use PVSS public verification
	return pvssSystem.VerifyShare(&pvssShare)
}

// GetShareInfo implements the SecretSharer interface for PVSS
func (p *PVSSSharer) GetShareInfo(share Share) ShareInfo {
	return share.Info
}

// ValidateConfig implements the SecretSharer interface for PVSS
func (p *PVSSSharer) ValidateConfig(config SecretSharingConfig) error {
	if config.Scheme != SchemePVSS {
		return fmt.Errorf("config is not for PVSS")
	}

	// PVSS currently supports single-level sharing only
	if len(config.Groups) != 1 {
		return fmt.Errorf("PVSS currently supports single-level sharing only (got %d groups)", len(config.Groups))
	}

	group := config.Groups[0]
	if group.MemberCount <= 0 {
		return fmt.Errorf("member count must be positive")
	}

	if group.MemberThreshold <= 0 {
		return fmt.Errorf("member threshold must be positive")
	}

	if group.MemberThreshold > group.MemberCount {
		return fmt.Errorf("threshold %d cannot exceed count %d",
			group.MemberThreshold, group.MemberCount)
	}

	// Validate curve type if specified
	if config.CurveType != "" && config.CurveType != string(pvss.CurveP256) {
		return fmt.Errorf("unsupported curve type: %s (supported: p256)", config.CurveType)
	}

	return nil
}

// GetScheme implements the SecretSharer interface for PVSS
func (p *PVSSSharer) GetScheme() SchemeType {
	return SchemePVSS
}

// ShareToString converts a PVSS share to a string representation
func (p *PVSSSharer) ShareToString(share Share) (string, error) {
	if share.Info.Scheme != SchemePVSS {
		return "", fmt.Errorf("share is not PVSS")
	}

	// Create a compact string representation
	// Format: PVSS:<identifier>:<group>:<member>:<base64-encoded-data>
	parts := []string{
		"PVSS",
		share.Info.Identifier,
		strconv.Itoa(share.Info.GroupIndex),
		strconv.Itoa(share.Info.MemberIndex),
		fmt.Sprintf("%x", share.Data),
	}

	return strings.Join(parts, ":"), nil
}

// ShareFromString creates a PVSS share from its string representation
func (p *PVSSSharer) ShareFromString(shareStr string) (Share, error) {
	parts := strings.Split(shareStr, ":")
	if len(parts) != 5 || parts[0] != "PVSS" {
		return Share{}, fmt.Errorf("invalid PVSS share format")
	}

	identifier := parts[1]
	
	groupIndex, err := strconv.Atoi(parts[2])
	if err != nil {
		return Share{}, fmt.Errorf("invalid group index: %w", err)
	}

	memberIndex, err := strconv.Atoi(parts[3])
	if err != nil {
		return Share{}, fmt.Errorf("invalid member index: %w", err)
	}

	data := make([]byte, len(parts[4])/2)
	_, err = fmt.Sscanf(parts[4], "%x", &data)
	if err != nil {
		return Share{}, fmt.Errorf("invalid data encoding: %w", err)
	}

	// We need more information to fully reconstruct the ShareInfo
	// This is a limitation of the string format - in practice, we'd need
	// additional metadata or a more comprehensive encoding
	share := Share{
		Info: ShareInfo{
			Scheme:       SchemePVSS,
			Identifier:   identifier,
			GroupIndex:   groupIndex,
			MemberIndex:  memberIndex,
			IsVerifiable: true,
		},
		Data: data,
	}

	return share, nil
}

// DetectPVSS attempts to detect if a string is a PVSS share
func DetectPVSS(input string) bool {
	return strings.HasPrefix(strings.TrimSpace(input), "PVSS:")
}

// init registers the PVSS sharer with the default registry
func init() {
	DefaultRegistry.Register(SchemePVSS, NewPVSSSharer())
}