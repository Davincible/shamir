// Package sharestore provides secure storage and management of secret shares
package sharestore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Davincible/shamir/pkg/crypto/secretsharing"
	"github.com/Davincible/shamir/pkg/secure"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// ShareSet represents a complete set of shares for a secret
type ShareSet struct {
	ID           string                   `json:"id"`
	Name         string                   `json:"name"`
	Description  string                   `json:"description"`
	Scheme       secretsharing.SchemeType `json:"scheme"`
	Created      time.Time                `json:"created"`
	Modified     time.Time                `json:"modified"`
	Threshold    int                      `json:"threshold"`
	TotalShares  int                      `json:"total_shares"`
	Groups       []GroupInfo              `json:"groups"`
	Tags         []string                 `json:"tags"`
	Metadata     map[string]string        `json:"metadata"`
	Shares       []ShareInfo              `json:"shares"`
	IsEncrypted  bool                     `json:"is_encrypted"`
	ChecksumSHA256 []byte                 `json:"checksum_sha256"`
}

// GroupInfo contains information about a share group
type GroupInfo struct {
	Index      int    `json:"index"`
	Threshold  int    `json:"threshold"`
	Count      int    `json:"count"`
	Name       string `json:"name"`
	Members    []int  `json:"members"`
}

// ShareInfo contains metadata and optionally encrypted share data
type ShareInfo struct {
	Index        int                  `json:"index"`
	GroupIndex   int                  `json:"group_index"`
	Name         string               `json:"name"`
	Location     string               `json:"location"`
	Status       ShareStatus          `json:"status"`
	Created      time.Time            `json:"created"`
	LastVerified *time.Time           `json:"last_verified,omitempty"`
	Share        *secretsharing.Share `json:"share,omitempty"` // Only if stored
	EncryptedData []byte              `json:"encrypted_data,omitempty"`
	Notes        string               `json:"notes"`
}

// ShareStatus represents the status of a share
type ShareStatus string

const (
	ShareStatusAvailable   ShareStatus = "available"
	ShareStatusMissing     ShareStatus = "missing"
	ShareStatusCorrupted   ShareStatus = "corrupted"
	ShareStatusUnverified  ShareStatus = "unverified"
	ShareStatusDistributed ShareStatus = "distributed"
)

// ShareStore manages collections of share sets
type ShareStore struct {
	storePath  string
	shareSets  map[string]*ShareSet
	encryption *EncryptionConfig
}

// EncryptionConfig contains encryption settings for the share store
type EncryptionConfig struct {
	Enabled    bool
	Passphrase string
	Salt       []byte
	KeyDerivationParams KeyDerivationParams
}

// KeyDerivationParams contains parameters for key derivation
type KeyDerivationParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// NewShareStore creates a new share store
func NewShareStore(storePath string) (*ShareStore, error) {
	store := &ShareStore{
		storePath: storePath,
		shareSets: make(map[string]*ShareSet),
	}
	
	// Create store directory if it doesn't exist
	if err := os.MkdirAll(storePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}
	
	// Load existing share sets
	if err := store.loadShareSets(); err != nil {
		return nil, fmt.Errorf("failed to load share sets: %w", err)
	}
	
	return store, nil
}

// EnableEncryption enables encryption for the share store
func (ss *ShareStore) EnableEncryption(passphrase string) error {
	// Generate salt
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	
	ss.encryption = &EncryptionConfig{
		Enabled:    true,
		Passphrase: passphrase,
		Salt:       salt,
		KeyDerivationParams: KeyDerivationParams{
			Time:    3,
			Memory:  64 * 1024, // 64MB
			Threads: 4,
		},
	}
	
	return nil
}

// AddShareSet adds a new share set to the store
func (ss *ShareStore) AddShareSet(shareSet *ShareSet) error {
	if shareSet.ID == "" {
		shareSet.ID = generateID()
	}
	
	if shareSet.Created.IsZero() {
		shareSet.Created = time.Now()
	}
	shareSet.Modified = time.Now()
	
	// Calculate checksum
	if err := ss.calculateChecksum(shareSet); err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	// Add to memory
	ss.shareSets[shareSet.ID] = shareSet
	
	// Persist to disk
	return ss.saveShareSet(shareSet)
}

// GetShareSet retrieves a share set by ID
func (ss *ShareStore) GetShareSet(id string) (*ShareSet, error) {
	shareSet, exists := ss.shareSets[id]
	if !exists {
		return nil, fmt.Errorf("share set '%s' not found", id)
	}
	
	// Verify checksum
	if err := ss.verifyChecksum(shareSet); err != nil {
		return nil, fmt.Errorf("checksum verification failed: %w", err)
	}
	
	return shareSet, nil
}

// ListShareSets returns all share sets, optionally filtered by tags
func (ss *ShareStore) ListShareSets(tags []string) []*ShareSet {
	var result []*ShareSet
	
	for _, shareSet := range ss.shareSets {
		if len(tags) == 0 || ss.hasAllTags(shareSet, tags) {
			result = append(result, shareSet)
		}
	}
	
	// Sort by creation time (newest first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Created.After(result[j].Created)
	})
	
	return result
}

// UpdateShareStatus updates the status of a specific share
func (ss *ShareStore) UpdateShareStatus(shareSetID string, shareIndex int, status ShareStatus) error {
	shareSet, err := ss.GetShareSet(shareSetID)
	if err != nil {
		return err
	}
	
	// Find the share
	for i := range shareSet.Shares {
		if shareSet.Shares[i].Index == shareIndex {
			shareSet.Shares[i].Status = status
			shareSet.Modified = time.Now()
			
			// Update checksum
			if err := ss.calculateChecksum(shareSet); err != nil {
				return err
			}
			
			return ss.saveShareSet(shareSet)
		}
	}
	
	return fmt.Errorf("share with index %d not found", shareIndex)
}

// VerifyShares verifies all shares in a share set
func (ss *ShareStore) VerifyShares(shareSetID string) (*VerificationReport, error) {
	shareSet, err := ss.GetShareSet(shareSetID)
	if err != nil {
		return nil, err
	}
	
	report := &VerificationReport{
		ShareSetID:    shareSetID,
		Timestamp:     time.Now(),
		TotalShares:   len(shareSet.Shares),
		Results:       make([]ShareVerificationResult, 0, len(shareSet.Shares)),
	}
	
	// Get the appropriate sharer
	sharer, err := secretsharing.DefaultRegistry.Get(shareSet.Scheme)
	if err != nil {
		return nil, fmt.Errorf("unsupported scheme: %w", err)
	}
	
	// Verify each share
	for i, shareInfo := range shareSet.Shares {
		result := ShareVerificationResult{
			ShareIndex: shareInfo.Index,
			Status:     shareInfo.Status,
		}
		
		if shareInfo.Share != nil {
			// Verify the share
			if err := sharer.Verify(*shareInfo.Share); err != nil {
				result.Error = err.Error()
				result.Status = ShareStatusCorrupted
			} else {
				result.Status = ShareStatusAvailable
				result.IsValid = true
			}
		} else {
			result.Status = ShareStatusMissing
			result.Error = "Share data not available"
		}
		
		// Update verification timestamp
		now := time.Now()
		shareSet.Shares[i].LastVerified = &now
		shareSet.Shares[i].Status = result.Status
		
		report.Results = append(report.Results, result)
		
		if result.IsValid {
			report.ValidShares++
		}
	}
	
	report.IsRecoverable = report.ValidShares >= shareSet.Threshold
	
	// Update modified time and save
	shareSet.Modified = time.Now()
	if err := ss.calculateChecksum(shareSet); err != nil {
		return nil, err
	}
	if err := ss.saveShareSet(shareSet); err != nil {
		return nil, err
	}
	
	return report, nil
}

// VerificationReport contains the results of share verification
type VerificationReport struct {
	ShareSetID    string                      `json:"share_set_id"`
	Timestamp     time.Time                   `json:"timestamp"`
	TotalShares   int                         `json:"total_shares"`
	ValidShares   int                         `json:"valid_shares"`
	IsRecoverable bool                        `json:"is_recoverable"`
	Results       []ShareVerificationResult   `json:"results"`
}

// ShareVerificationResult contains verification results for a single share
type ShareVerificationResult struct {
	ShareIndex int         `json:"share_index"`
	Status     ShareStatus `json:"status"`
	IsValid    bool        `json:"is_valid"`
	Error      string      `json:"error,omitempty"`
}

// GetRecoveryShares returns the shares needed for recovery
func (ss *ShareStore) GetRecoveryShares(shareSetID string) ([]secretsharing.Share, error) {
	shareSet, err := ss.GetShareSet(shareSetID)
	if err != nil {
		return nil, err
	}
	
	var availableShares []secretsharing.Share
	
	// Collect available shares
	for _, shareInfo := range shareSet.Shares {
		if shareInfo.Status == ShareStatusAvailable && shareInfo.Share != nil {
			// Decrypt if necessary
			share := shareInfo.Share
			if shareInfo.EncryptedData != nil {
				decryptedShare, err := ss.decryptShare(shareInfo.EncryptedData)
				if err != nil {
					continue // Skip corrupted shares
				}
				share = decryptedShare
			}
			availableShares = append(availableShares, *share)
		}
	}
	
	// Check if we have enough shares
	if len(availableShares) < shareSet.Threshold {
		return nil, fmt.Errorf("insufficient shares: need %d, have %d", 
			shareSet.Threshold, len(availableShares))
	}
	
	// Return exactly the threshold number of shares
	return availableShares[:shareSet.Threshold], nil
}

// DeleteShareSet removes a share set from the store
func (ss *ShareStore) DeleteShareSet(id string) error {
	shareSet, exists := ss.shareSets[id]
	if !exists {
		return fmt.Errorf("share set '%s' not found", id)
	}
	
	// Remove from memory
	delete(ss.shareSets, id)
	
	// Remove from disk
	filename := ss.getShareSetFilename(shareSet)
	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
	}
	
	return nil
}

// SearchShareSets searches share sets by name, description, or tags
func (ss *ShareStore) SearchShareSets(query string) []*ShareSet {
	query = strings.ToLower(query)
	var results []*ShareSet
	
	for _, shareSet := range ss.shareSets {
		if ss.matchesQuery(shareSet, query) {
			results = append(results, shareSet)
		}
	}
	
	// Sort by relevance (exact name matches first, then creation time)
	sort.Slice(results, func(i, j int) bool {
		iExact := strings.ToLower(results[i].Name) == query
		jExact := strings.ToLower(results[j].Name) == query
		
		if iExact && !jExact {
			return true
		}
		if !iExact && jExact {
			return false
		}
		
		return results[i].Created.After(results[j].Created)
	})
	
	return results
}

// ExportShareSet exports a share set to a portable format
func (ss *ShareStore) ExportShareSet(id string, includeShares bool) (*ExportData, error) {
	shareSet, err := ss.GetShareSet(id)
	if err != nil {
		return nil, err
	}
	
	export := &ExportData{
		Version:   "1.0",
		Timestamp: time.Now(),
		ShareSet:  *shareSet,
	}
	
	if !includeShares {
		// Remove sensitive data
		for i := range export.ShareSet.Shares {
			export.ShareSet.Shares[i].Share = nil
			export.ShareSet.Shares[i].EncryptedData = nil
		}
	}
	
	return export, nil
}

// ImportShareSet imports a share set from exported data
func (ss *ShareStore) ImportShareSet(exportData *ExportData, overwrite bool) error {
	// Check if already exists
	if !overwrite {
		if _, exists := ss.shareSets[exportData.ShareSet.ID]; exists {
			return fmt.Errorf("share set with ID '%s' already exists", exportData.ShareSet.ID)
		}
	}
	
	// Import the share set
	shareSet := exportData.ShareSet
	shareSet.Modified = time.Now()
	
	return ss.AddShareSet(&shareSet)
}

// ExportData represents exported share set data
type ExportData struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	ShareSet  ShareSet  `json:"share_set"`
}

// Helper methods

func (ss *ShareStore) loadShareSets() error {
	entries, err := os.ReadDir(ss.storePath)
	if err != nil {
		return err
	}
	
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			if err := ss.loadShareSetFromFile(filepath.Join(ss.storePath, entry.Name())); err != nil {
				// Log error but continue loading other files
				continue
			}
		}
	}
	
	return nil
}

func (ss *ShareStore) loadShareSetFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	
	// Decrypt if necessary
	if ss.encryption != nil && ss.encryption.Enabled {
		data, err = ss.decrypt(data)
		if err != nil {
			return err
		}
	}
	
	var shareSet ShareSet
	if err := json.Unmarshal(data, &shareSet); err != nil {
		return err
	}
	
	// Verify checksum
	if err := ss.verifyChecksum(&shareSet); err != nil {
		return err
	}
	
	ss.shareSets[shareSet.ID] = &shareSet
	return nil
}

func (ss *ShareStore) saveShareSet(shareSet *ShareSet) error {
	filename := ss.getShareSetFilename(shareSet)
	
	data, err := json.MarshalIndent(shareSet, "", "  ")
	if err != nil {
		return err
	}
	
	// Encrypt if necessary
	if ss.encryption != nil && ss.encryption.Enabled {
		data, err = ss.encrypt(data)
		if err != nil {
			return err
		}
	}
	
	return os.WriteFile(filename, data, 0600)
}

func (ss *ShareStore) getShareSetFilename(shareSet *ShareSet) string {
	safeName := strings.ReplaceAll(shareSet.Name, " ", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")
	if len(safeName) > 50 {
		safeName = safeName[:50]
	}
	return filepath.Join(ss.storePath, fmt.Sprintf("%s_%s.json", safeName, shareSet.ID[:8]))
}

func (ss *ShareStore) calculateChecksum(shareSet *ShareSet) error {
	// Create a copy without the checksum field for calculation
	temp := *shareSet
	temp.ChecksumSHA256 = nil
	
	data, err := json.Marshal(temp)
	if err != nil {
		return err
	}
	
	hash := sha256.Sum256(data)
	shareSet.ChecksumSHA256 = hash[:]
	
	return nil
}

func (ss *ShareStore) verifyChecksum(shareSet *ShareSet) error {
	if len(shareSet.ChecksumSHA256) == 0 {
		// Legacy share set without checksum
		return nil
	}
	
	originalChecksum := make([]byte, len(shareSet.ChecksumSHA256))
	copy(originalChecksum, shareSet.ChecksumSHA256)
	
	// Calculate current checksum
	if err := ss.calculateChecksum(shareSet); err != nil {
		return err
	}
	
	// Compare
	if !secure.ConstantTimeCompare(originalChecksum, shareSet.ChecksumSHA256) {
		return fmt.Errorf("checksum mismatch - data may be corrupted")
	}
	
	return nil
}

func (ss *ShareStore) hasAllTags(shareSet *ShareSet, tags []string) bool {
	shareSetTags := make(map[string]bool)
	for _, tag := range shareSet.Tags {
		shareSetTags[strings.ToLower(tag)] = true
	}
	
	for _, tag := range tags {
		if !shareSetTags[strings.ToLower(tag)] {
			return false
		}
	}
	
	return true
}

func (ss *ShareStore) matchesQuery(shareSet *ShareSet, query string) bool {
	// Check name
	if strings.Contains(strings.ToLower(shareSet.Name), query) {
		return true
	}
	
	// Check description
	if strings.Contains(strings.ToLower(shareSet.Description), query) {
		return true
	}
	
	// Check tags
	for _, tag := range shareSet.Tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}
	
	// Check metadata
	for key, value := range shareSet.Metadata {
		if strings.Contains(strings.ToLower(key), query) ||
			strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	
	return false
}

func (ss *ShareStore) encrypt(data []byte) ([]byte, error) {
	if ss.encryption == nil || !ss.encryption.Enabled {
		return data, nil
	}
	
	// Derive key
	key := argon2.IDKey(
		[]byte(ss.encryption.Passphrase),
		ss.encryption.Salt,
		ss.encryption.KeyDerivationParams.Time,
		ss.encryption.KeyDerivationParams.Memory,
		ss.encryption.KeyDerivationParams.Threads,
		32,
	)
	
	// Create cipher
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	
	// Generate nonce
	nonce := make([]byte, cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	
	// Encrypt
	encrypted := cipher.Seal(nil, nonce, data, nil)
	
	// Prepend salt and nonce
	result := make([]byte, 0, len(ss.encryption.Salt)+len(nonce)+len(encrypted))
	result = append(result, ss.encryption.Salt...)
	result = append(result, nonce...)
	result = append(result, encrypted...)
	
	return result, nil
}

func (ss *ShareStore) decrypt(data []byte) ([]byte, error) {
	if ss.encryption == nil || !ss.encryption.Enabled {
		return data, nil
	}
	
	if len(data) < 32+12 { // salt + nonce minimum
		return nil, fmt.Errorf("encrypted data too short")
	}
	
	// Extract salt and nonce
	salt := data[:32]
	nonceStart := 32
	nonceEnd := nonceStart + 12
	nonce := data[nonceStart:nonceEnd]
	encrypted := data[nonceEnd:]
	
	// Derive key
	key := argon2.IDKey(
		[]byte(ss.encryption.Passphrase),
		salt,
		ss.encryption.KeyDerivationParams.Time,
		ss.encryption.KeyDerivationParams.Memory,
		ss.encryption.KeyDerivationParams.Threads,
		32,
	)
	
	// Create cipher
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	
	// Decrypt
	decrypted, err := cipher.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	return decrypted, nil
}

func (ss *ShareStore) decryptShare(encryptedData []byte) (*secretsharing.Share, error) {
	decrypted, err := ss.decrypt(encryptedData)
	if err != nil {
		return nil, err
	}
	
	var share secretsharing.Share
	if err := json.Unmarshal(decrypted, &share); err != nil {
		return nil, err
	}
	
	return &share, nil
}

func generateID() string {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", bytes)
}