package slip039

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// VectorTestCase represents a test case from the official test vectors
type VectorTestCase []interface{}

func TestOfficialVectors(t *testing.T) {
	// Test against official SLIP-0039 test vectors to ensure spec compliance
	// Load test vectors
	vectorsPath := filepath.Join("..", "..", "..", "docs", "slip-0039-vectors.json")
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Skipf("Test vectors not found: %v", err)
		return
	}
	
	var vectors []VectorTestCase
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse test vectors: %v", err)
	}
	
	passphrase := "TREZOR" // Standard passphrase for test vectors
	
	for i, vector := range vectors {
		if len(vector) < 4 {
			continue
		}
		
		description, ok := vector[0].(string)
		if !ok {
			continue
		}
		
		mnemonicsRaw, ok := vector[1].([]interface{})
		if !ok {
			continue
		}
		
		expectedSecretHex, ok := vector[2].(string)
		if !ok {
			continue
		}
		
		// Skip invalid test cases (empty expected secret)
		if expectedSecretHex == "" {
			t.Logf("Test %d: %s - Skipping (invalid/error case)", i+1, description)
			continue
		}
		
		// Convert mnemonics
		mnemonics := make([]string, len(mnemonicsRaw))
		for j, m := range mnemonicsRaw {
			mnemonic, ok := m.(string)
			if !ok {
				t.Errorf("Test %d: Invalid mnemonic format", i+1)
				continue
			}
			mnemonics[j] = mnemonic
		}
		
		// Decode expected secret
		expectedSecret, err := hex.DecodeString(expectedSecretHex)
		if err != nil {
			t.Errorf("Test %d: Failed to decode expected secret: %v", i+1, err)
			continue
		}
		
		t.Run(description, func(t *testing.T) {
			// Validate each mnemonic
			for j, mnemonic := range mnemonics {
				if err := ValidateMnemonic(mnemonic); err != nil {
					t.Errorf("Mnemonic %d validation failed: %v", j+1, err)
				}
			}
			
			// Try to recover the secret
			recoveredSecret, err := RecoverMasterSecret(mnemonics, passphrase)
			if err != nil {
				t.Errorf("Failed to recover secret: %v", err)
				return
			}
			
			// Compare with expected
			if !bytes.Equal(recoveredSecret, expectedSecret) {
				t.Errorf("Secret mismatch")
				t.Errorf("Expected: %x", expectedSecret)
				t.Errorf("Got:      %x", recoveredSecret)
			}
		})
	}
}

func TestVectorErrorCases(t *testing.T) {
	// Test cases that should fail
	invalidCases := []struct {
		name      string
		mnemonics []string
	}{
		{
			name: "Invalid checksum",
			mnemonics: []string{
				"duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney",
			},
		},
		{
			name: "Insufficient shares",
			mnemonics: []string{
				"shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
			},
		},
		{
			name: "Different identifiers",
			mnemonics: []string{
				"adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate",
				"adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner",
			},
		},
	}
	
	passphrase := "TREZOR"
	
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RecoverMasterSecret(tc.mnemonics, passphrase)
			if err == nil {
				t.Error("Expected error but recovery succeeded")
			}
			t.Logf("Got expected error: %v", err)
		})
	}
}

// TestRoundTrip tests that we can split and recover various secrets
func TestRoundTrip(t *testing.T) {
	testCases := []struct {
		name           string
		secretHex      string
		groupThreshold byte
		groups         []GroupConfiguration
	}{
		{
			name:           "128-bit single group 2-of-3",
			secretHex:      "bb54aac4b89dc868ba37d9cc21b2cece",
			groupThreshold: 1,
			groups:         SimpleConfiguration(2, 3),
		},
		{
			name:           "256-bit single group 3-of-5",
			secretHex:      "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			groupThreshold: 1,
			groups:         SimpleConfiguration(3, 5),
		},
		{
			name:           "128-bit two groups",
			secretHex:      "aabbccddeeff00112233445566778899",
			groupThreshold: 2,
			groups: []GroupConfiguration{
				{MemberThreshold: 2, MemberCount: 3},
				{MemberThreshold: 2, MemberCount: 3},
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secret, err := hex.DecodeString(tc.secretHex)
			if err != nil {
				t.Fatalf("Failed to decode secret: %v", err)
			}
			
			// Test with empty passphrase
			mnemonics, err := SplitMasterSecret(secret, "", tc.groupThreshold, tc.groups)
			if err != nil {
				t.Fatalf("Failed to split secret: %v", err)
			}
			
			// Collect minimum shares
			var selectedShares []string
			groupsNeeded := int(tc.groupThreshold)
			
			for i := 0; i < groupsNeeded && i < len(mnemonics); i++ {
				membersNeeded := int(tc.groups[i].MemberThreshold)
				for j := 0; j < membersNeeded && j < len(mnemonics[i]); j++ {
					selectedShares = append(selectedShares, mnemonics[i][j])
				}
			}
			
			// Recover secret
			recovered, err := RecoverMasterSecret(selectedShares, "")
			if err != nil {
				t.Fatalf("Failed to recover secret: %v", err)
			}
			
			if !bytes.Equal(secret, recovered) {
				t.Errorf("Secret mismatch")
				t.Errorf("Original:  %x", secret)
				t.Errorf("Recovered: %x", recovered)
			}
			
			// Test with passphrase
			passphrase := "test passphrase"
			mnemonicsP, err := SplitMasterSecret(secret, passphrase, tc.groupThreshold, tc.groups)
			if err != nil {
				t.Fatalf("Failed to split with passphrase: %v", err)
			}
			
			// Collect shares again
			selectedShares = selectedShares[:0]
			for i := 0; i < groupsNeeded && i < len(mnemonicsP); i++ {
				membersNeeded := int(tc.groups[i].MemberThreshold)
				for j := 0; j < membersNeeded && j < len(mnemonicsP[i]); j++ {
					selectedShares = append(selectedShares, mnemonicsP[i][j])
				}
			}
			
			// Recover with correct passphrase
			recoveredP, err := RecoverMasterSecret(selectedShares, passphrase)
			if err != nil {
				t.Fatalf("Failed to recover with passphrase: %v", err)
			}
			
			if !bytes.Equal(secret, recoveredP) {
				t.Errorf("Secret with passphrase mismatch")
			}
			
			// Recover with wrong passphrase (should succeed but give different result)
			recoveredWrong, err := RecoverMasterSecret(selectedShares, "wrong")
			if err != nil {
				t.Fatalf("Failed to recover with wrong passphrase: %v", err)
			}
			
			if bytes.Equal(secret, recoveredWrong) {
				t.Error("Wrong passphrase gave correct secret (should be different)")
			}
		})
	}
}