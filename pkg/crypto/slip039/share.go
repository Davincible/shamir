package slip039

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

// ShareCommonParameters contains parameters common to all shares in a set
type ShareCommonParameters struct {
	Identifier        uint16 // 15-bit random identifier
	Extendable        bool   // Extendable backup flag
	IterationExponent byte   // Iteration exponent for PBKDF2
	GroupThreshold    byte   // Number of groups required (GT)
	GroupCount        byte   // Total number of groups (G)
}

// Share represents a single SLIP-0039 share
type Share struct {
	CommonParameters  ShareCommonParameters
	GroupIndex        byte   // Index of the group (0-based)
	MemberIndex       byte   // Index within the group (0-based)
	MemberThreshold   byte   // Number of members required in this group (T)
	ShareValue        []byte // The actual share data
}

// ShareGroup represents a group of member shares
type ShareGroup struct {
	GroupIndex      byte
	MemberThreshold byte
	MemberCount     byte
	Members         []Share
}

// SharingConfiguration defines how to split a secret
type SharingConfiguration struct {
	Groups []GroupConfiguration
}

// GroupConfiguration defines a single group's parameters
type GroupConfiguration struct {
	MemberThreshold byte
	MemberCount     byte
}

// Validate checks if the sharing configuration is valid
func (c *SharingConfiguration) Validate() error {
	if len(c.Groups) == 0 {
		return fmt.Errorf("at least one group is required")
	}
	
	if len(c.Groups) > 16 {
		return fmt.Errorf("maximum 16 groups allowed, got %d", len(c.Groups))
	}
	
	for i, group := range c.Groups {
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

// encodeShareData encodes share metadata and value into bit array
func (s *Share) encodeShareData() []int {
	// The share value contains the full integer value (with padding bits)
	// compressed into fewer bytes. We need to expand it back to words.
	
	// Convert share value bytes to a big integer
	value := big.NewInt(0).SetBytes(s.ShareValue)
	
	// Calculate how many value words we need
	// The share value is stored with padding bits compressed into it
	// For 128-bit secret (16 bytes): needs 130 bits total = 13 words
	// For 256-bit secret (32 bytes): needs 260 bits total = 26 words
	shareValueBits := len(s.ShareValue) * 8
	
	// Calculate total bits needed (must be divisible by both 10 and have proper padding)
	// Padding formula: we need the next multiple of 10 that gives us proper mod 16 padding
	var totalValueBits int
	if shareValueBits == 128 {
		totalValueBits = 130 // 13 words * 10 bits, 2 padding bits
	} else if shareValueBits == 256 {
		totalValueBits = 260 // 26 words * 10 bits, 4 padding bits
	} else {
		// General case: find next multiple of 10 that's >= shareValueBits
		totalValueBits = ((shareValueBits + 9) / 10) * 10
	}
	
	numValueWords := totalValueBits / 10
	
	// Pack metadata (40 bits = 4 words)
	metadata := uint64(0)
	
	// Identifier (15 bits)
	metadata |= uint64(s.CommonParameters.Identifier&0x7FFF) << 25
	
	// Extendable flag (1 bit)
	if s.CommonParameters.Extendable {
		metadata |= uint64(1) << 24
	}
	
	// Iteration exponent (4 bits)
	metadata |= uint64(s.CommonParameters.IterationExponent&0xF) << 20
	
	// Group index (4 bits)
	metadata |= uint64(s.GroupIndex&0xF) << 16
	
	// Group threshold - 1 (4 bits)
	metadata |= uint64((s.CommonParameters.GroupThreshold-1)&0xF) << 12
	
	// Group count - 1 (4 bits)
	metadata |= uint64((s.CommonParameters.GroupCount-1)&0xF) << 8
	
	// Member index (4 bits)
	metadata |= uint64(s.MemberIndex&0xF) << 4
	
	// Member threshold - 1 (4 bits)
	metadata |= uint64((s.MemberThreshold-1)&0xF) << 0
	
	// Convert to word array
	totalWords := 4 + numValueWords // 4 metadata words + value words
	words := make([]int, 0, totalWords)
	
	// Add metadata words (4 words)
	words = append(words, int((metadata>>30)&0x3FF))
	words = append(words, int((metadata>>20)&0x3FF))
	words = append(words, int((metadata>>10)&0x3FF))
	words = append(words, int(metadata&0x3FF))
	
	// Convert the big integer value to words
	// We need to extract words in reverse order (from least significant)
	// then reverse them for the final encoding
	radix := big.NewInt(1024)
	valueWords := make([]int, numValueWords)
	temp := new(big.Int).Set(value)
	
	for i := numValueWords - 1; i >= 0; i-- {
		mod := new(big.Int)
		temp.DivMod(temp, radix, mod)
		valueWords[i] = int(mod.Int64())
	}
	
	// Append value words to the result
	words = append(words, valueWords...)
	
	return words
}

// decodeShareData decodes share data from word array
func decodeShareData(words []int) (*Share, error) {
	if len(words) < 7 { // Minimum: 4 metadata + 3 checksum
		return nil, fmt.Errorf("share too short: %d words", len(words))
	}
	
	// Remove checksum (last 3 words)
	dataWords := words[:len(words)-3]
	
	if len(dataWords) < 4 {
		return nil, fmt.Errorf("insufficient metadata words")
	}
	
	// Decode metadata (first 4 words = 40 bits)
	metadata := uint64(0)
	metadata |= uint64(dataWords[0]&0x3FF) << 30
	metadata |= uint64(dataWords[1]&0x3FF) << 20
	metadata |= uint64(dataWords[2]&0x3FF) << 10
	metadata |= uint64(dataWords[3]&0x3FF) << 0
	
	share := &Share{
		CommonParameters: ShareCommonParameters{
			Identifier:        uint16((metadata >> 25) & 0x7FFF),
			Extendable:        (metadata>>24)&1 == 1,
			IterationExponent: byte((metadata >> 20) & 0xF),
			GroupThreshold:    byte(((metadata >> 12) & 0xF) + 1),
			GroupCount:        byte(((metadata >> 8) & 0xF) + 1),
		},
		GroupIndex:      byte((metadata >> 16) & 0xF),
		MemberIndex:     byte((metadata >> 4) & 0xF),
		MemberThreshold: byte((metadata & 0xF) + 1),
	}
	
	// Decode share value
	valueWords := dataWords[4:]
	if len(valueWords) == 0 {
		return nil, fmt.Errorf("no share value data")
	}
	
	// IMPORTANT: The Python reference implementation keeps padding bits!
	// It converts all words to a big integer (including padding) and then
	// encodes that into the calculated byte count.
	
	// Use big.Int to avoid overflow with many words
	value := big.NewInt(0)
	radix := big.NewInt(1024)
	
	for _, word := range valueWords {
		value.Mul(value, radix)
		value.Add(value, big.NewInt(int64(word)))
	}
	
	// Calculate the byte count based on bits WITHOUT padding
	totalBits := len(valueWords) * 10
	paddingBits := totalBits % 16
	valueBits := totalBits - paddingBits
	valueByteCount := (valueBits + 7) / 8
	
	// Convert the FULL value (with padding) to bytes
	shareBytes := value.Bytes()
	
	// Ensure we have exactly the right number of bytes
	if len(shareBytes) < valueByteCount {
		// Pad with zeros at the front
		padded := make([]byte, valueByteCount)
		copy(padded[valueByteCount-len(shareBytes):], shareBytes)
		shareBytes = padded
	} else if len(shareBytes) > valueByteCount {
		// If the value is too large, we need to handle it
		// This shouldn't happen with valid mnemonics
		return nil, fmt.Errorf("share value too large: got %d bytes, expected %d", len(shareBytes), valueByteCount)
	}
	
	share.ShareValue = shareBytes
	
	return share, nil
}

// ToMnemonic converts a share to a mnemonic phrase
func (s *Share) ToMnemonic() (string, error) {
	// Encode share data
	words := s.encodeShareData()
	
	// Add checksum
	wordsWithChecksum := addChecksum(words, s.CommonParameters.Extendable)
	
	// Convert to mnemonic
	return indicesToMnemonic(wordsWithChecksum)
}

// ShareFromMnemonic creates a share from a mnemonic phrase
func ShareFromMnemonic(mnemonic string) (*Share, error) {
	// Convert mnemonic to indices
	indices, err := mnemonicToIndices(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}
	
	// Minimum length check
	if len(indices) < 7 {
		return nil, fmt.Errorf("mnemonic too short: %d words (minimum 7)", len(indices))
	}
	
	// Decode share to get extendable flag for checksum verification
	tempShare, err := decodeShareData(indices)
	if err != nil {
		return nil, err
	}
	
	// Verify checksum
	dataWords, err := verifyChecksum(indices, tempShare.CommonParameters.Extendable)
	if err != nil {
		return nil, fmt.Errorf("checksum verification failed: %w", err)
	}
	
	// Decode share data
	share, err := decodeShareData(append(dataWords, indices[len(indices)-3:]...))
	if err != nil {
		return nil, fmt.Errorf("failed to decode share: %w", err)
	}
	
	return share, nil
}

// generateIdentifier generates a random 15-bit identifier
func generateIdentifier() (uint16, error) {
	var buf [2]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return 0, err
	}
	
	// Mask to 15 bits
	return binary.BigEndian.Uint16(buf[:]) & 0x7FFF, nil
}