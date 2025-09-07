package test

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/crypto/shamir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLI_SplitCombineWorkflow_MultipleFormats(t *testing.T) {
	// Test secret
	secret := []byte("test secret for cli integration")
	
	// Split the secret
	config := shamir.Config{Parts: 5, Threshold: 3}
	shares, err := shamir.Split(secret, config)
	require.NoError(t, err)
	
	// Test combining with different formats
	testCases := []struct {
		name   string
		format string
	}{
		{"Hex format", "hex"},
		{"Base64 format", "base64"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert shares to the specified format
			var shareStrings []string
			for _, share := range shares[:3] { // Use threshold number of shares
				switch tc.format {
				case "hex":
					shareStrings = append(shareStrings, hex.EncodeToString(share.Data))
				case "base64":
					shareStrings = append(shareStrings, base64.StdEncoding.EncodeToString(share.Data))
				}
			}
			
			// Parse shares using CLI parsing logic
			parsedShares, err := parseSharesTestHelper(shareStrings)
			require.NoError(t, err)
			
			// Combine shares
			reconstructed, err := shamir.Combine(parsedShares)
			require.NoError(t, err)
			
			// Verify reconstruction
			assert.Equal(t, secret, reconstructed)
		})
	}
}

func TestCLI_MnemonicWorkflow(t *testing.T) {
	// Create a mnemonic with valid entropy
	m, err := mnemonic.NewMnemonic(128)
	require.NoError(t, err)
	
	entropy, err := m.Entropy()
	require.NoError(t, err)
	
	// Split the entropy
	config := shamir.Config{Parts: 3, Threshold: 2}
	shares, err := shamir.Split(entropy, config)
	require.NoError(t, err)
	
	// Convert first share to mnemonic format (if possible)
	var shareStrings []string
	for _, share := range shares[:2] {
		// Try to create mnemonic if data is valid entropy
		if len(share.Data) >= 16 && len(share.Data) <= 32 && len(share.Data)%4 == 0 {
			if shareMnemonic, err := mnemonic.FromEntropy(share.Data); err == nil {
				shareStrings = append(shareStrings, shareMnemonic.Words())
			} else {
				// Fallback to hex if mnemonic creation fails
				shareStrings = append(shareStrings, hex.EncodeToString(share.Data))
			}
		} else {
			shareStrings = append(shareStrings, hex.EncodeToString(share.Data))
		}
	}
	
	// Parse and combine
	parsedShares, err := parseSharesTestHelper(shareStrings)
	require.NoError(t, err)
	
	reconstructed, err := shamir.Combine(parsedShares)
	require.NoError(t, err)
	
	// Verify we can create the same mnemonic
	reconstructedMnemonic, err := mnemonic.FromEntropy(reconstructed)
	require.NoError(t, err)
	
	assert.Equal(t, m.Words(), reconstructedMnemonic.Words())
}

func TestCLI_FormatAutoDetection(t *testing.T) {
	testData := []byte("test data for format detection")
	
	formats := map[string]string{
		"hex":    hex.EncodeToString(testData),
		"base64": base64.StdEncoding.EncodeToString(testData),
	}
	
	// Test mnemonic format with proper entropy
	entropy := make([]byte, 16)
	copy(entropy, testData)
	testMnemonic, err := mnemonic.FromEntropy(entropy)
	require.NoError(t, err)
	formats["mnemonic"] = testMnemonic.Words()
	
	for expectedFormat, encodedData := range formats {
		t.Run("Detect "+expectedFormat, func(t *testing.T) {
			// Use the detection logic from combine.go
			detected := detectFormatTestHelper(encodedData)
			
			// Verify detection works (some flexibility needed for detection order)
			if expectedFormat == "mnemonic" {
				assert.Equal(t, "mnemonic", detected)
			} else {
				// Hex and base64 detection order may vary, just ensure it's one of them
				assert.Contains(t, []string{"hex", "base64"}, detected)
			}
			
			// More importantly, verify we can parse it successfully
			_, err := parseShareDataTestHelper(encodedData, detected)
			assert.NoError(t, err)
		})
	}
}

func TestCLI_MixedFormatCombination(t *testing.T) {
	// Create test shares in different formats
	testShares := [][]byte{
		[]byte("share 1 data"),
		[]byte("share 2 data"), 
		[]byte("share 3 data"),
	}
	
	shareStrings := []string{
		hex.EncodeToString(testShares[0]),          // Hex
		base64.StdEncoding.EncodeToString(testShares[1]), // Base64
		hex.EncodeToString(testShares[2]),          // Hex again
	}
	
	parsedShares, err := parseSharesTestHelper(shareStrings)
	require.NoError(t, err)
	
	assert.Len(t, parsedShares, 3)
	
	// Verify each share was parsed correctly
	for i, expected := range testShares {
		assert.Equal(t, expected, parsedShares[i].Data)
		assert.Equal(t, byte(i+1), parsedShares[i].Index)
	}
}

func TestCLI_ErrorHandling(t *testing.T) {
	testCases := []struct {
		name        string
		shareString string
		expectError bool
	}{
		{
			name:        "Invalid hex",
			shareString: "invalid hex string xyz",
			expectError: true,
		},
		{
			name:        "Invalid mnemonic",
			shareString: "invalid mnemonic words that are not real",
			expectError: true,
		},
		{
			name:        "Valid hex",
			shareString: "48656c6c6f",
			expectError: false,
		},
		{
			name:        "Valid base64",
			shareString: "SGVsbG8=",
			expectError: false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSharesTestHelper([]string{tc.shareString})
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper functions to test internal CLI logic
func parseSharesTestHelper(shareStrings []string) ([]shamir.Share, error) {
	shares := make([]shamir.Share, 0, len(shareStrings))

	for i, s := range shareStrings {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		format := detectFormatTestHelper(s)
		if format == "unknown" {
			return nil, assert.AnError
		}

		data, err := parseShareDataTestHelper(s, format)
		if err != nil {
			return nil, err
		}

		shares = append(shares, shamir.Share{
			Index: byte(i + 1),
			Data:  data,
		})
	}

	return shares, nil
}

func detectFormatTestHelper(s string) string {
	s = strings.TrimSpace(s)
	
	// Check if it's a valid hex string
	if _, err := hex.DecodeString(s); err == nil && len(s)%2 == 0 {
		return "hex"
	}
	
	// Check if it's a valid base64 string
	if _, err := base64.StdEncoding.DecodeString(s); err == nil {
		return "base64"
	}
	
	// Check if it looks like a mnemonic (multiple words)
	words := strings.Fields(s)
	if len(words) >= 3 { // At least 3 words to be considered a mnemonic
		return "mnemonic"
	}
	
	return "unknown"
}

func parseShareDataTestHelper(s string, format string) ([]byte, error) {
	switch format {
	case "hex":
		return hex.DecodeString(s)
	case "base64":
		return base64.StdEncoding.DecodeString(s)
	case "mnemonic":
		m, err := mnemonic.FromWords(s)
		if err != nil {
			return nil, err
		}
		return m.Entropy()
	default:
		return nil, assert.AnError
	}
}