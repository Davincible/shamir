// Package pvss implements mnemonic encoding for PVSS shares
package pvss

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

// MnemonicShare represents a PVSS share encoded as a mnemonic
type MnemonicShare struct {
	Mnemonic   string                `json:"mnemonic"`
	Metadata   *ShareMetadata        `json:"metadata"`
	Commitment *PolynomialCommitment `json:"commitment"`
}

// ShareMetadata contains metadata about the PVSS share
type ShareMetadata struct {
	Version        uint8     `json:"version"`
	Identifier     string    `json:"identifier"`
	Index          int       `json:"index"`
	Threshold      int       `json:"threshold"`
	TotalShares    int       `json:"total_shares"`
	CurveType      CurveType `json:"curve_type"`
	ChecksumBytes  []byte    `json:"checksum"`
}

// EncodeMnemonic encodes a PVSS share as a BIP39-style mnemonic
func (pvss *PVSSSystem) EncodeMnemonic(share *PVSSShare) (*MnemonicShare, error) {
	if share == nil {
		return nil, fmt.Errorf("share cannot be nil")
	}

	// Create metadata
	metadata := &ShareMetadata{
		Version:     1,
		Identifier:  pvss.generateIdentifier(share),
		Index:       share.Index,
		Threshold:   pvss.Threshold,
		TotalShares: pvss.NumShares,
		CurveType:   pvss.Params.CurveType,
	}

	// Serialize share data
	shareData := pvss.serializeShare(share)
	
	// Add metadata prefix
	metadataBytes := pvss.serializeMetadata(metadata)
	fullData := append(metadataBytes, shareData...)
	
	// Add checksum
	checksum := sha256.Sum256(fullData)
	metadata.ChecksumBytes = checksum[:4]
	fullData = append(fullData, checksum[:4]...)
	
	// Pad to nearest valid entropy size for BIP39
	entropySize := pvss.calculateEntropySize(len(fullData))
	paddedData := pvss.padData(fullData, entropySize)
	
	// Generate mnemonic
	mnemonic, err := bip39.NewMnemonic(paddedData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}
	
	return &MnemonicShare{
		Mnemonic:   mnemonic,
		Metadata:   metadata,
		Commitment: share.Commitment,
	}, nil
}

// DecodeMnemonic decodes a mnemonic back to a PVSS share
func (pvss *PVSSSystem) DecodeMnemonic(mnemonicShare *MnemonicShare) (*PVSSShare, error) {
	if mnemonicShare == nil {
		return nil, fmt.Errorf("mnemonic share cannot be nil")
	}

	// Validate mnemonic
	if !bip39.IsMnemonicValid(mnemonicShare.Mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}
	
	// Convert mnemonic to entropy
	entropy, err := bip39.EntropyFromMnemonic(mnemonicShare.Mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to extract entropy from mnemonic: %w", err)
	}
	
	// Extract and verify checksum
	if len(entropy) < 4 {
		return nil, fmt.Errorf("entropy too short")
	}
	
	checksumStart := pvss.findChecksumStart(entropy)
	providedChecksum := entropy[checksumStart : checksumStart+4]
	dataWithoutChecksum := entropy[:checksumStart]
	
	// Verify checksum
	calculatedChecksum := sha256.Sum256(dataWithoutChecksum)
	if !bytesEqual(providedChecksum, calculatedChecksum[:4]) {
		return nil, fmt.Errorf("checksum verification failed")
	}
	
	// Extract metadata and share data
	metadata, shareDataStart := pvss.deserializeMetadata(dataWithoutChecksum)
	if metadata == nil {
		return nil, fmt.Errorf("failed to deserialize metadata")
	}
	
	shareData := dataWithoutChecksum[shareDataStart:]
	
	// Reconstruct PVSS share
	share := pvss.deserializeShare(shareData, metadata)
	share.Commitment = mnemonicShare.Commitment
	
	return share, nil
}

// generateIdentifier generates a unique identifier for a PVSS share set
func (pvss *PVSSSystem) generateIdentifier(share *PVSSShare) string {
	if share.Commitment != nil && len(share.Commitment.Commitments) > 0 {
		first := share.Commitment.Commitments[0]
		data := append(first.X.Bytes(), first.Y.Bytes()...)
		hash := sha256.Sum256(data)
		return fmt.Sprintf("%08X", hash[:4])
	}
	return "00000000"
}

// serializeShare serializes a PVSS share to bytes
func (pvss *PVSSSystem) serializeShare(share *PVSSShare) []byte {
	// Serialize the share value (32 bytes for P-256)
	valueBytes := make([]byte, 32)
	share.Value.FillBytes(valueBytes)
	
	return valueBytes
}

// deserializeShare deserializes bytes back to a PVSS share
func (pvss *PVSSSystem) deserializeShare(data []byte, metadata *ShareMetadata) *PVSSShare {
	if len(data) < 32 {
		// Pad if necessary
		padded := make([]byte, 32)
		copy(padded[32-len(data):], data)
		data = padded
	}
	
	value := new(big.Int).SetBytes(data[:32])
	
	return &PVSSShare{
		Index: metadata.Index,
		Value: value,
	}
}

// serializeMetadata serializes share metadata to bytes
func (pvss *PVSSSystem) serializeMetadata(metadata *ShareMetadata) []byte {
	// Fixed size metadata encoding (16 bytes)
	data := make([]byte, 16)
	
	// Version (1 byte)
	data[0] = metadata.Version
	
	// Identifier (4 bytes)
	id, _ := fmt.Sscanf(metadata.Identifier, "%08X")
	binary.BigEndian.PutUint32(data[1:5], uint32(id))
	
	// Index (2 bytes)
	binary.BigEndian.PutUint16(data[5:7], uint16(metadata.Index))
	
	// Threshold (2 bytes)
	binary.BigEndian.PutUint16(data[7:9], uint16(metadata.Threshold))
	
	// Total shares (2 bytes)
	binary.BigEndian.PutUint16(data[9:11], uint16(metadata.TotalShares))
	
	// Curve type (1 byte)
	data[11] = pvss.curveTypeToByte(metadata.CurveType)
	
	// Reserved (4 bytes)
	// data[12:16] = 0
	
	return data
}

// deserializeMetadata deserializes bytes back to metadata
func (pvss *PVSSSystem) deserializeMetadata(data []byte) (*ShareMetadata, int) {
	if len(data) < 16 {
		return nil, 0
	}
	
	metadata := &ShareMetadata{
		Version:     data[0],
		Identifier:  fmt.Sprintf("%08X", binary.BigEndian.Uint32(data[1:5])),
		Index:       int(binary.BigEndian.Uint16(data[5:7])),
		Threshold:   int(binary.BigEndian.Uint16(data[7:9])),
		TotalShares: int(binary.BigEndian.Uint16(data[9:11])),
		CurveType:   pvss.byteToCurveType(data[11]),
	}
	
	return metadata, 16
}

// curveTypeToByte converts curve type to byte
func (pvss *PVSSSystem) curveTypeToByte(ct CurveType) byte {
	switch ct {
	case CurveP256:
		return 0x01
	default:
		return 0x00
	}
}

// byteToCurveType converts byte to curve type
func (pvss *PVSSSystem) byteToCurveType(b byte) CurveType {
	switch b {
	case 0x01:
		return CurveP256
	default:
		return CurveP256
	}
}

// calculateEntropySize calculates the appropriate entropy size for BIP39
func (pvss *PVSSSystem) calculateEntropySize(dataLen int) int {
	// BIP39 valid entropy sizes: 128, 160, 192, 224, 256 bits
	// In bytes: 16, 20, 24, 28, 32
	validSizes := []int{16, 20, 24, 28, 32}
	
	for _, size := range validSizes {
		if dataLen <= size {
			return size
		}
	}
	
	// For larger data, use 32 bytes and hash
	return 32
}

// padData pads data to the target size
func (pvss *PVSSSystem) padData(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		// If data is too large, hash it down
		hash := sha256.Sum256(data)
		return hash[:targetSize]
	}
	
	// Pad with zeros
	padded := make([]byte, targetSize)
	copy(padded, data)
	return padded
}

// findChecksumStart finds where the checksum starts in the data
func (pvss *PVSSSystem) findChecksumStart(data []byte) int {
	// Checksum is always the last 4 bytes before padding
	// Look for the actual data end
	for i := len(data) - 4; i >= 0; i-- {
		if i+4 <= len(data) {
			// Check if this could be a valid position
			testData := data[:i]
			if len(testData) >= 16 { // Minimum metadata size
				return i
			}
		}
	}
	return len(data) - 4
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FormatMnemonicShare formats a mnemonic share for display
func FormatMnemonicShare(share *MnemonicShare) string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("PVSS Share #%d (Threshold: %d/%d)\n",
		share.Metadata.Index,
		share.Metadata.Threshold,
		share.Metadata.TotalShares))
	sb.WriteString(fmt.Sprintf("Identifier: %s\n", share.Metadata.Identifier))
	sb.WriteString(fmt.Sprintf("Curve: %s\n", share.Metadata.CurveType))
	sb.WriteString(fmt.Sprintf("\nMnemonic:\n%s\n", share.Mnemonic))
	
	return sb.String()
}

// ParseMnemonicShare parses a mnemonic string into a MnemonicShare
func ParseMnemonicShare(mnemonic string, commitmentJSON string) (*MnemonicShare, error) {
	// Validate mnemonic
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}
	
	// Parse commitment if provided
	var commitment *PolynomialCommitment
	if commitmentJSON != "" {
		commitment = &PolynomialCommitment{}
		if err := json.Unmarshal([]byte(commitmentJSON), commitment); err != nil {
			return nil, fmt.Errorf("failed to parse commitment: %w", err)
		}
	}
	
	// Extract basic metadata from mnemonic
	// This is a simplified version - in practice, we'd decode the full metadata
	return &MnemonicShare{
		Mnemonic:   mnemonic,
		Commitment: commitment,
	}, nil
}