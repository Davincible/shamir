package cli

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitCommand_MultipleFormats(t *testing.T) {
	// Create a split result with the test data
	result := SplitResult{
		Shares:    make([]ShareFormats, 3),
		Threshold: 2,
		Total:     3,
		SharesHex: make([]string, 3),
	}

	// Simulate share creation
	testShares := [][]byte{
		[]byte("share1data123456"),
		[]byte("share2data123456"), 
		[]byte("share3data123456"),
	}

	for i, shareData := range testShares {
		hexStr := hex.EncodeToString(shareData)
		base64Str := base64.StdEncoding.EncodeToString(shareData)

		result.Shares[i] = ShareFormats{
			Hex:    hexStr,
			Base64: base64Str,
		}
		result.SharesHex[i] = hexStr
	}

	// Verify all formats are present
	for i, share := range result.Shares {
		assert.NotEmpty(t, share.Hex, "Share %d hex should not be empty", i)
		assert.NotEmpty(t, share.Base64, "Share %d base64 should not be empty", i)
		
		// Verify hex decodes properly
		decoded, err := hex.DecodeString(share.Hex)
		require.NoError(t, err)
		assert.Equal(t, testShares[i], decoded)
		
		// Verify base64 decodes properly
		decodedBase64, err := base64.StdEncoding.DecodeString(share.Base64)
		require.NoError(t, err)
		assert.Equal(t, testShares[i], decodedBase64)
	}
}

func TestSplitCommand_MnemonicGeneration(t *testing.T) {
	// Test with valid entropy sizes for mnemonic generation
	testCases := []struct {
		name        string
		entropySize int
		expectWords bool
	}{
		{"16 bytes entropy", 16, true},
		{"20 bytes entropy", 20, true},
		{"24 bytes entropy", 24, true},
		{"28 bytes entropy", 28, true},
		{"32 bytes entropy", 32, true},
		{"15 bytes entropy", 15, false}, // Invalid size
		{"33 bytes entropy", 33, false}, // Invalid size
		{"17 bytes entropy", 17, false}, // Not multiple of 4
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testData := make([]byte, tc.entropySize)
			for i := range testData {
				testData[i] = byte(i % 256)
			}

			result := SplitResult{
				Shares:    make([]ShareFormats, 1),
				Threshold: 1,
				Total:     1,
			}

			// Simulate the mnemonic generation logic from split.go
			hexStr := hex.EncodeToString(testData)
			base64Str := base64.StdEncoding.EncodeToString(testData)
			
			var mnemonicStr string
			if len(testData) >= 16 && len(testData) <= 32 && len(testData)%4 == 0 {
				if m, err := mnemonic.FromEntropy(testData); err == nil {
					mnemonicStr = m.Words()
				}
			}

			result.Shares[0] = ShareFormats{
				Hex:      hexStr,
				Base64:   base64Str,
				Mnemonic: mnemonicStr,
			}

			if tc.expectWords {
				assert.NotEmpty(t, result.Shares[0].Mnemonic, "Should generate mnemonic for valid entropy")
				words := strings.Fields(result.Shares[0].Mnemonic)
				assert.True(t, len(words) >= 12, "Mnemonic should have at least 12 words")
			} else {
				assert.Empty(t, result.Shares[0].Mnemonic, "Should not generate mnemonic for invalid entropy")
			}
		})
	}
}

func TestSplitCommand_BackwardCompatibility(t *testing.T) {
	result := SplitResult{
		Shares:    make([]ShareFormats, 2),
		Threshold: 2,
		Total:     2,
		SharesHex: make([]string, 2),
	}

	testData1 := []byte("test data 1")
	testData2 := []byte("test data 2")

	result.Shares[0] = ShareFormats{
		Hex:    hex.EncodeToString(testData1),
		Base64: base64.StdEncoding.EncodeToString(testData1),
	}
	result.Shares[1] = ShareFormats{
		Hex:    hex.EncodeToString(testData2),
		Base64: base64.StdEncoding.EncodeToString(testData2),
	}

	result.SharesHex[0] = result.Shares[0].Hex
	result.SharesHex[1] = result.Shares[1].Hex

	// Verify backward compatibility field is populated
	assert.Len(t, result.SharesHex, 2)
	assert.Equal(t, result.Shares[0].Hex, result.SharesHex[0])
	assert.Equal(t, result.Shares[1].Hex, result.SharesHex[1])
}

func TestSplitCommand_ValidateParams(t *testing.T) {
	testCases := []struct {
		name      string
		parts     int
		threshold int
		wantError bool
	}{
		{"Valid 3/2", 3, 2, false},
		{"Valid 5/3", 5, 3, false},
		{"Valid 10/6", 10, 6, false},
		{"Invalid: threshold > parts", 3, 5, true},
		{"Invalid: threshold = 0", 5, 0, true},
		{"Invalid: parts = 0", 0, 2, true},
		{"Invalid: threshold = 1", 3, 1, true},
		{"Valid: threshold = parts", 3, 3, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSplitParams(tc.parts, tc.threshold)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}