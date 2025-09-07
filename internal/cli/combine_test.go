package cli

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectFormat(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedFormat string
	}{
		{
			name:           "Valid hex",
			input:          "48656c6c6f20576f726c64",
			expectedFormat: "hex",
		},
		{
			name:           "Valid hex with spaces",
			input:          " 48656c6c6f20576f726c64 ",
			expectedFormat: "hex",
		},
		{
			name:           "Valid base64",
			input:          "SGVsbG8gV29ybGQ=",
			expectedFormat: "base64",
		},
		{
			name:           "Valid mnemonic",
			input:          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			expectedFormat: "mnemonic",
		},
		{
			name:           "Short mnemonic (valid)",
			input:          "hello world test",
			expectedFormat: "mnemonic",
		},
		{
			name:           "Too short for mnemonic",
			input:          "hello world",
			expectedFormat: "unknown", // Too short, invalid base64
		},
		{
			name:           "Invalid format",
			input:          "xyz",
			expectedFormat: "unknown", // Invalid format
		},
		{
			name:           "Empty string",
			input:          "",
			expectedFormat: "hex", // Empty hex string is valid
		},
		{
			name:           "Mixed case hex",
			input:          "48656C6C6F20576F726C64",
			expectedFormat: "hex",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			format := detectFormat(tc.input)
			assert.Equal(t, tc.expectedFormat, format)
		})
	}
}

func TestParseShareData(t *testing.T) {
	testData := []byte("Hello World")
	hexStr := hex.EncodeToString(testData)
	base64Str := base64.StdEncoding.EncodeToString(testData)
	
	// Create a test mnemonic with valid entropy
	entropy := make([]byte, 16)
	if len(testData) >= 16 {
		copy(entropy, testData[:16])
	} else {
		copy(entropy, testData)
		for i := len(testData); i < 16; i++ {
			entropy[i] = 0
		}
	}
	testMnemonic, err := mnemonic.FromEntropy(entropy)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		input       string
		format      string
		expected    []byte
		expectError bool
	}{
		{
			name:     "Parse hex",
			input:    hexStr,
			format:   "hex",
			expected: testData,
		},
		{
			name:     "Parse base64",
			input:    base64Str,
			format:   "base64",
			expected: testData,
		},
		{
			name:     "Parse mnemonic",
			input:    testMnemonic.Words(),
			format:   "mnemonic",
			expected: entropy,
		},
		{
			name:     "Valid short hex",
			input:    "12", // Short but valid hex
			format:   "hex",
			expected: []byte{0x12},
		},
		{
			name:        "Invalid mnemonic",
			input:       "invalid mnemonic words here",
			format:      "mnemonic",
			expectError: true,
		},
		{
			name:        "Unknown format",
			input:       "test",
			format:      "unknown",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseShareData(tc.input, tc.format)
			
			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseShares(t *testing.T) {
	// Create test data
	testData1 := []byte("test share 1")
	testData2 := []byte("test share 2")
	
	hexShare1 := hex.EncodeToString(testData1)
	hexShare2 := hex.EncodeToString(testData2)
	
	base64Share1 := base64.StdEncoding.EncodeToString(testData1)
	
	// Create valid entropy for mnemonic
	entropy := make([]byte, 16)
	copy(entropy, testData1)
	testMnemonic, err := mnemonic.FromEntropy(entropy)
	require.NoError(t, err)

	testCases := []struct {
		name         string
		shareStrings []string
		expectError  bool
		expectedLen  int
	}{
		{
			name:         "Valid hex shares",
			shareStrings: []string{hexShare1, hexShare2},
			expectError:  false,
			expectedLen:  2,
		},
		{
			name:         "Mixed formats",
			shareStrings: []string{hexShare1, base64Share1, testMnemonic.Words()},
			expectError:  false,
			expectedLen:  3,
		},
		{
			name:         "Empty strings ignored",
			shareStrings: []string{hexShare1, "", hexShare2},
			expectError:  false,
			expectedLen:  2,
		},
		{
			name:         "Invalid format",
			shareStrings: []string{hexShare1, "!@#$%^&*()", hexShare2},
			expectError:  true,
		},
		{
			name:         "All empty",
			shareStrings: []string{"", " ", "\t"},
			expectError:  false,
			expectedLen:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shares, err := parseShares(tc.shareStrings)
			
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, shares, tc.expectedLen)
				
				// Verify share indices are set correctly
				for i, share := range shares {
					assert.Equal(t, byte(i+1), share.Index)
					assert.NotEmpty(t, share.Data)
				}
			}
		})
	}
}

func TestParseShares_FormatDetection(t *testing.T) {
	testData := []byte("test data for format detection")
	
	hexStr := hex.EncodeToString(testData)
	base64Str := base64.StdEncoding.EncodeToString(testData)
	
	// Test that the same data can be parsed in different formats
	testCases := []struct {
		name   string
		input  string
		format string
	}{
		{"Hex detection", hexStr, "hex"},
		{"Base64 detection", base64Str, "base64"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			detected := detectFormat(tc.input)
			assert.Equal(t, tc.format, detected)
			
			// Verify parsing works
			shares, err := parseShares([]string{tc.input})
			require.NoError(t, err)
			assert.Len(t, shares, 1)
		})
	}
}

func TestCombineInput_JSONCompatibility(t *testing.T) {
	// Test that CombineInput struct works with JSON unmarshaling
	input := CombineInput{
		Shares: []string{
			"48656c6c6f20576f726c64",
			"546573742064617461",
		},
	}
	
	assert.Len(t, input.Shares, 2)
	assert.NotEmpty(t, input.Shares[0])
	assert.NotEmpty(t, input.Shares[1])
}