// Package secretsharing provides a unified interface for various Secret Sharing Schemes
// including SLIP-0039 and PVSS (Publicly Verifiable Secret Sharing)
package secretsharing

import (
	"fmt"
)

// SchemeType represents the type of secret sharing scheme
type SchemeType string

const (
	// SchemeSLIP039 represents the SLIP-0039 standard
	SchemeSLIP039 SchemeType = "slip039"
	// SchemePVSS represents Publicly Verifiable Secret Sharing
	SchemePVSS SchemeType = "pvss"
)

// ShareInfo contains metadata about a share
type ShareInfo struct {
	Scheme          SchemeType `json:"scheme"`
	Identifier      string     `json:"identifier"`
	GroupIndex      int        `json:"group_index"`
	GroupThreshold  int        `json:"group_threshold"`
	GroupCount      int        `json:"group_count"`
	MemberIndex     int        `json:"member_index"`
	MemberThreshold int        `json:"member_threshold"`
	IsVerifiable    bool       `json:"is_verifiable"`
}

// Share represents a single share in any secret sharing scheme
type Share struct {
	Info     ShareInfo `json:"info"`
	Data     []byte    `json:"data"`
	Mnemonic string    `json:"mnemonic,omitempty"`
	
	// PVSS-specific fields
	Commitment []byte `json:"commitment,omitempty"`
	Proof      []byte `json:"proof,omitempty"`
}

// GroupConfiguration defines parameters for a group
type GroupConfiguration struct {
	MemberThreshold int `json:"member_threshold"`
	MemberCount     int `json:"member_count"`
}

// SecretSharingConfig contains configuration for secret sharing
type SecretSharingConfig struct {
	Scheme         SchemeType            `json:"scheme"`
	GroupThreshold int                   `json:"group_threshold"`
	Groups         []GroupConfiguration  `json:"groups"`
	Passphrase     string                `json:"-"` // Never serialize
	Extendable     bool                  `json:"extendable,omitempty"`
	
	// PVSS-specific configuration
	CurveType      string                `json:"curve_type,omitempty"`
	PublicParams   []byte                `json:"public_params,omitempty"`
}

// SecretSharer defines the interface for secret sharing schemes
type SecretSharer interface {
	// Split splits a secret into shares according to the configuration
	Split(secret []byte, config SecretSharingConfig) ([]Share, error)
	
	// Combine reconstructs the secret from shares
	Combine(shares []Share, passphrase string) ([]byte, error)
	
	// Verify verifies that a share is valid (public verification for PVSS)
	Verify(share Share) error
	
	// GetShareInfo extracts metadata from a share
	GetShareInfo(share Share) ShareInfo
	
	// ValidateConfig validates the sharing configuration
	ValidateConfig(config SecretSharingConfig) error
	
	// GetScheme returns the scheme type this sharer implements
	GetScheme() SchemeType
}

// SharerRegistry manages different secret sharing implementations
type SharerRegistry struct {
	sharers map[SchemeType]SecretSharer
}

// NewRegistry creates a new sharer registry
func NewRegistry() *SharerRegistry {
	return &SharerRegistry{
		sharers: make(map[SchemeType]SecretSharer),
	}
}

// Register registers a secret sharer implementation
func (r *SharerRegistry) Register(scheme SchemeType, sharer SecretSharer) {
	r.sharers[scheme] = sharer
}

// Get retrieves a sharer for the given scheme
func (r *SharerRegistry) Get(scheme SchemeType) (SecretSharer, error) {
	sharer, exists := r.sharers[scheme]
	if !exists {
		return nil, fmt.Errorf("unsupported scheme: %s", scheme)
	}
	return sharer, nil
}

// ListSchemes returns all registered schemes
func (r *SharerRegistry) ListSchemes() []SchemeType {
	schemes := make([]SchemeType, 0, len(r.sharers))
	for scheme := range r.sharers {
		schemes = append(schemes, scheme)
	}
	return schemes
}

// Default registry instance
var DefaultRegistry = NewRegistry()

// Convenience functions using the default registry

// Split splits a secret using the specified scheme
func Split(secret []byte, config SecretSharingConfig) ([]Share, error) {
	sharer, err := DefaultRegistry.Get(config.Scheme)
	if err != nil {
		return nil, err
	}
	return sharer.Split(secret, config)
}

// Combine reconstructs a secret from shares
func Combine(shares []Share, passphrase string) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}
	
	scheme := shares[0].Info.Scheme
	sharer, err := DefaultRegistry.Get(scheme)
	if err != nil {
		return nil, err
	}
	return sharer.Combine(shares, passphrase)
}

// Verify verifies a share using the appropriate scheme
func Verify(share Share) error {
	sharer, err := DefaultRegistry.Get(share.Info.Scheme)
	if err != nil {
		return err
	}
	return sharer.Verify(share)
}

// GetShareInfo extracts metadata from a share
func GetShareInfo(share Share) ShareInfo {
	return share.Info
}